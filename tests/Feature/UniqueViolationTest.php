<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\AuthEmailChanges;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\AuthRegistration;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\Support\UniqueViolation;
use Nvl\Auth\Tests\Fixtures\TestUser;

afterEach(function (): void {
    Schema::dropIfExists('acme_challenges');
    Schema::dropIfExists('acme_changes');
});

it('names the violated unique index of a configured table on every driver without knowing its index name', function (): void {
    Schema::create('acme_challenges', static function (Blueprint $table): void {
        $table->id();
        $table->char('active_key', 64)->nullable()->unique();
        $table->char('secret_hash', 64)->unique('host_named_secret_index');
        $table->string('client_id', 32);
        $table->char('session_hash', 64);
        $table->unique(['client_id', 'session_hash']);
    });
    Schema::create('acme_changes', static function (Blueprint $table): void {
        $table->id();
        $table->char('active_key', 64)->nullable()->unique();
    });
    $connection = DB::connection();
    $violation = static function (string $table, array $row) use ($connection): UniqueConstraintViolationException {
        try {
            $connection->transaction(static fn () => $connection->table($table)->insert($row));
        } catch (UniqueConstraintViolationException $exception) {
            return $exception;
        }
        throw new RuntimeException('The duplicate row was accepted.');
    };
    $row = ['active_key' => 'a', 'secret_hash' => 's', 'client_id' => 'c', 'session_hash' => 'h'];
    $connection->table('acme_challenges')->insert($row);
    $connection->table('acme_changes')->insert(['active_key' => 'a']);

    $active = $violation('acme_challenges', [...$row, 'secret_hash' => 's2', 'session_hash' => 'h2']);
    $secret = $violation('acme_challenges', [...$row, 'active_key' => 'a2', 'session_hash' => 'h2']);
    $composite = $violation('acme_challenges', [...$row, 'active_key' => 'a2', 'secret_hash' => 's2']);
    $other = $violation('acme_changes', ['active_key' => 'a']);

    expect(UniqueViolation::columns($active, $connection, 'acme_challenges'))->toBe(['active_key'])
        ->and(UniqueViolation::columns($secret, $connection, 'acme_challenges'))->toBe(['secret_hash'])
        ->and(UniqueViolation::columns($composite, $connection, 'acme_challenges'))->toBe(['client_id', 'session_hash'])
        ->and(UniqueViolation::columns($other, $connection, 'acme_challenges'))->toBeNull()
        ->and(UniqueViolation::columns($other, $connection, 'acme_changes'))->toBe(['active_key']);
});

it('translates only a principal uniqueness violation into the invited-principal conflict', function (string $failure, string $expected): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'invitation_only', 'nvl-auth.features.invitations.enabled' => true]);
    $token = 'unique-violation-token';
    Invitation::factory()->create(['recipient' => 'violation@example.test', 'token_hash' => app(SecretHasher::class)->hash('invitation-token', $token)]);
    Role::query()->create(['name' => 'taken', 'guard_name' => 'web']);
    app()->bind(InvitationSubjectResolver::class, static fn () => new class($failure) implements InvitationSubjectResolver
    {
        public function __construct(private string $failure) {}

        public function resolve(Invitation $invitation, #[SensitiveParameter] array $input): Authenticatable
        {
            $roles = (new Role)->getTable();
            DB::transaction(fn () => match ($this->failure) {
                'principal' => TestUser::query()->create(['email' => 'taken@example.test', 'name' => 'Second', 'password' => 'second-password']),
                'other unique index' => DB::table($roles)->insert(['id' => (string) Str::uuid(), 'name' => 'taken', 'guard_name' => 'web']),
                default => DB::table($roles)->insert(['id' => (string) Str::uuid(), 'name' => null, 'guard_name' => 'web']),
            });
            throw new RuntimeException('The conflicting write was accepted.');
        }
    });
    TestUser::query()->create(['email' => 'taken@example.test', 'name' => 'First', 'password' => 'first-password']);
    $caught = null;
    try {
        app(AuthInvitations::class)->register(['token' => $token, 'name' => 'Signup', 'password' => 'new-password-123', 'passwordConfirmation' => 'new-password-123']);
    } catch (Throwable $exception) {
        $caught = $exception;
    }

    expect($caught)->toBeInstanceOf($expected);
    if ($caught instanceof AuthException) {
        expect($caught->errorCode)->toBe('invitation_principal_conflict');
    }
})->with([
    'principal' => ['principal', AuthException::class],
    'other unique index' => ['other unique index', UniqueConstraintViolationException::class],
    'not-null violation' => ['not-null violation', QueryException::class],
]);

it('reports only an identity uniqueness violation as an unavailable registration', function (): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open']);
    Role::query()->create(['name' => 'taken', 'guard_name' => 'web']);
    $class = app(AuthModelRegistry::class)->userClass();
    $class::creating(static function (): void {
        DB::transaction(static fn () => DB::table((new Role)->getTable())->insert(['id' => (string) Str::uuid(), 'name' => 'taken', 'guard_name' => 'web']));
    });

    expect(fn () => app(AuthRegistration::class)->register(['name' => 'Signup', 'email' => 'signup@example.test', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123']))
        ->toThrow(UniqueConstraintViolationException::class);
});

it('reports only a principal uniqueness violation as an invalid email change', function (): void {
    config(['nvl-auth.features.email_verification.enabled' => true]);
    $user = $this->user();
    $context = $this->authenticationContext();
    $grant = $this->recentGrant($user, RecentAuthenticationPurpose::EmailChange)->reveal();
    Event::fake([AuthDeliveryRequested::class]);
    $service = app(AuthEmailChanges::class);
    $service->request($user, 'next@example.test', $grant, $context);
    $token = Event::dispatched(AuthDeliveryRequested::class)->first(fn ($args) => $args[0]->request->type === AuthMessageType::EmailChangeVerification)[0]->request->payload['token'];
    Role::query()->create(['name' => 'taken', 'guard_name' => 'web']);
    $user::updating(static function (): void {
        DB::transaction(static fn () => DB::table((new Role)->getTable())->insert(['id' => (string) Str::uuid(), 'name' => 'taken', 'guard_name' => 'web']));
    });

    expect(fn () => $service->complete($user, $token, $context))->toThrow(UniqueConstraintViolationException::class);
});
