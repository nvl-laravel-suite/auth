<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Event;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\PrincipalExtensionMapper;
use Nvl\Auth\Enums\PrincipalMutation;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\PersonalAccessToken;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Tests\Fixtures\CalendarPrincipal;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Auth\Tests\StatefulAuthTestCase;

uses(StatefulAuthTestCase::class);

beforeEach(function (): void {
    $connection = (new User)->getConnection();
    $timezone = date_default_timezone_get();
    $applicationTimezone = config('app.timezone');
    $sessionTimezone = $connection->getDriverName() === 'pgsql' ? $connection->scalar('SHOW TimeZone') : null;
    $this->beforeApplicationDestroyed(function () use ($connection, $timezone, $applicationTimezone, $sessionTimezone): void {
        try {
            $this->travelBack();
            if ($sessionTimezone !== null) {
                $connection->selectOne("SELECT set_config('TimeZone', ?, false)", [$sessionTimezone]);
            }
        } finally {
            config()->set('app.timezone', $applicationTimezone);
            date_default_timezone_set($timezone);
        }
    });
    config()->set('app.timezone', 'Europe/Sofia');
    date_default_timezone_set('Europe/Sofia');
    if ($sessionTimezone !== null) {
        $connection->selectOne("SELECT set_config('TimeZone', ?, false)", ['America/New_York']);
    }
    $this->travelTo(CarbonImmutable::parse('2026-11-01T12:34:56Z'));
});

it('preserves host calendar and formatted date casts through configured principal extensions', function (): void {
    (new User)->getConnection()->getSchemaBuilder()->table((new User)->getTable(), static function (Blueprint $table): void {
        $table->date('profile_date')->nullable();
        $table->date('profile_immutable_date')->nullable();
        $table->date('profile_formatted_date')->nullable();
        $table->dateTime('profile_local_time')->nullable();
    });
    config()->set('nvl-auth.features.principal_management.models.user', CalendarPrincipal::class);
    config()->set('auth.providers.users.model', CalendarPrincipal::class);
    app()->forgetInstance(AuthModelRegistry::class);
    app()->instance(PrincipalExtensionMapper::class, new class implements PrincipalExtensionMapper
    {
        public function validateAndMap(PrincipalMutation $mutation, array $extensions, ?User $principal = null): array
        {
            return [
                'profile_date' => $extensions['profileDate'],
                'profile_immutable_date' => $extensions['profileDate'],
                'profile_formatted_date' => $extensions['profileDate'],
                'profile_local_time' => $extensions['profileTime'],
            ];
        }
    });

    $user = app(AuthUsers::class)->create($this->user(), [
        'name' => 'Calendar', 'email' => 'calendar@example.test', 'password' => 'SecurePassword123',
        'extensions' => ['profileDate' => '2026-11-01', 'profileTime' => '2026-11-01 08:30:00'],
    ])->fresh();

    expect($user)->toBeInstanceOf(CalendarPrincipal::class)
        ->and($user->profile_date->toDateString())->toBe('2026-11-01')
        ->and($user->profile_immutable_date)->toBeInstanceOf(CarbonImmutable::class)
        ->and($user->profile_immutable_date->toDateString())->toBe('2026-11-01')
        ->and($user->toArray()['profile_formatted_date'])->toBe('2026-11-01')
        ->and($user->toArray()['profile_local_time'])->toBe('2026-11-01 08:30');
});

it('round trips native creation touch and upsert epochs with distinct application and database timezones', function (string $kind): void {
    $instant = CarbonImmutable::parse('2026-11-01T12:34:56Z');
    $record = match ($kind) {
        'principal' => $this->user(),
        'auth model' => Challenge::factory()->create(),
        'token' => PersonalAccessToken::factory()->create(),
    };
    expect($record->fresh()->created_at->getTimestamp())->toBe($instant->getTimestamp());
    $this->travelTo($instant->addMinute());
    $record->touch();
    expect($record->fresh()->updated_at->getTimestamp())->toBe($instant->addMinute()->getTimestamp());

    $this->travelTo($instant->addMinutes(2));
    $attributes = $record->getRawOriginal();
    unset($attributes[$record->getCreatedAtColumn()], $attributes[$record->getUpdatedAtColumn()]);
    $record->newQuery()->upsert([$attributes], [$record->getKeyName()], [$record->getUpdatedAtColumn()]);
    expect($record->fresh()->updated_at->getTimestamp())->toBe($instant->addMinutes(2)->getTimestamp())
        ->and($record->fresh()->created_at->getTimestamp())->toBe($instant->getTimestamp());
})->with(['principal', 'auth model', 'token']);

it('retains soft deletion events originals and mapped timestamp epochs', function (bool $mapped): void {
    $connection = (new User)->getConnection();
    if ($mapped) {
        $connection->getSchemaBuilder()->table((new User)->getTable(), static function (Blueprint $table): void {
            $table->renameColumn('created_at', 'host_created_at');
            $table->renameColumn('updated_at', 'host_updated_at');
            $table->renameColumn('deleted_at', 'host_deleted_at');
        });
        config()->set('nvl-auth.features.principal_management.settings.attributes.created_at', 'host_created_at');
        config()->set('nvl-auth.features.principal_management.settings.attributes.updated_at', 'host_updated_at');
        config()->set('nvl-auth.features.principal_management.settings.attributes.deleted_at', 'host_deleted_at');
        app()->forgetInstance(PrincipalAttributeMapper::class);
    }
    $instant = CarbonImmutable::parse('2026-11-01T12:34:56Z');
    $record = $this->user();
    Event::fake(['eloquent.trashed: '.TestUser::class]);
    $record->delete();
    $stored = TestUser::withTrashed()->findOrFail($record->getKey());
    expect($stored->getAttribute($stored->getCreatedAtColumn())->getTimestamp())->toBe($instant->getTimestamp())
        ->and($stored->getAttribute($stored->getDeletedAtColumn())->getTimestamp())->toBe($instant->getTimestamp())
        ->and($stored->getAttribute($stored->getUpdatedAtColumn())->getTimestamp())->toBe($instant->getTimestamp())
        ->and($record->isDirty())->toBeFalse();
    Event::assertDispatched('eloquent.trashed: '.TestUser::class);
    $stored->restore();
    $this->travelTo($instant->addMinute());
    TestUser::query()->whereKey($stored->getKey())->delete();
    $stored = TestUser::withTrashed()->findOrFail($stored->getKey());
    expect($stored->getAttribute($stored->getDeletedAtColumn())->getTimestamp())->toBe($instant->addMinute()->getTimestamp())
        ->and($stored->getAttribute($stored->getUpdatedAtColumn())->getTimestamp())->toBe($instant->addMinute()->getTimestamp());
})->with([false, true]);
