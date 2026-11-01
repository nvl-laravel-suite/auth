<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Nvl\Auth\Contracts\AccountAuthenticationPolicy;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Events\AccountSecurityChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Services\AuthAccountSecurity;
use Nvl\Auth\Services\AuthPasskeys;
use Nvl\Auth\Services\AuthTokens;
use Nvl\Auth\Services\UsableAccountAuthenticationPolicy;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Auth\ValueObjects\IssuedRecentAuthentication;

it('preserves authentication instants in a non UTC PostgreSQL session', function (string $timezone): void {
    $connection = DB::connection();
    if ($connection->getDriverName() !== 'pgsql') {
        $this->markTestSkipped('PostgreSQL session timezone regression.');
    }
    $original = $connection->scalar('SHOW TimeZone');
    try {
        $connection->selectOne("SELECT set_config('TimeZone', ?, false)", [$timezone]);
        $now = CarbonImmutable::now('UTC')->startOfSecond();
        $this->travelTo($now);
        $expiresAt = $now->addMinute();
        $challenge = Challenge::factory()->create(['expires_at' => $expiresAt]);
        expect($challenge->refresh()->expires_at->getTimestamp())->toBe($expiresAt->getTimestamp());
        $user = $this->user();
        expect($this->recentGrant($user, RecentAuthenticationPurpose::FactorRemoval))->toBeInstanceOf(IssuedRecentAuthentication::class);
        $token = app(AuthTokens::class)->create($user, ['name' => 'Timezone expiry', 'abilities' => ['profile:read'], 'expiresAt' => $expiresAt]);
        expect($token->token['expiresAt']?->getTimestamp())->toBe($expiresAt->getTimestamp())
            ->and($token->token['createdAt']->getTimestamp())->toBe($now->getTimestamp())
            ->and($user->fresh()?->created_at?->getTimestamp())->toBe($now->getTimestamp());
        $user->update(['locked_until' => $expiresAt]);
        expect($user->fresh()?->isAuthenticationAllowed())->toBeFalse()
            ->and(TestUser::query()->authenticationAllowed()->whereKey($user->id)->exists())->toBeFalse();
        $user->delete();
        expect(TestUser::withTrashed()->findOrFail($user->id)->deleted_at?->getTimestamp())->toBe($now->getTimestamp());
    } finally {
        $this->travelBack();
        $connection->selectOne("SELECT set_config('TimeZone', ?, false)", [$original]);
    }
})->with(['Europe/Sofia', 'America/New_York']);

it('returns only usable owned authentication methods without credentials', function (): void {
    config(['nvl-auth.features.passkeys.enabled' => true]);
    $user = $this->user();
    $other = $this->user('other@example.test');
    $passkey = Passkey::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    Passkey::factory()->forSubject($other)->create(['subject_type' => $other->getMorphClass()]);
    Passkey::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass(), 'revoked_at' => now()]);
    $state = app(AuthAccountSecurity::class)->state($user);
    expect($state['hasPassword'])->toBeTrue()->and($state['passkeys'])->toHaveCount(1)->and($state['passkeys'][0]['id'])->toBe($passkey->identifier());
    expect(json_encode($state))->not->toContain('public_key', 'credential_id', 'secret', 'password_hash');
});

it('rejects final primary removal and foreign credential identifiers under the native lock', function (): void {
    config(['nvl-auth.features.passkeys.enabled' => true]);
    $user = $this->user();
    $policy = app(UsableAccountAuthenticationPolicy::class);
    expect(fn () => $user->getConnection()->transaction(fn () => $policy->assertRemovalAllowed($user, 'password', 'password')))->toThrow(AuthException::class);
    $passkey = Passkey::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $user->getConnection()->transaction(fn () => $policy->assertRemovalAllowed($user, 'password', 'password'));
    expect(fn () => $user->getConnection()->transaction(fn () => $policy->assertRemovalAllowed($user, 'passkey', 'foreign')))->toThrow(AuthException::class);
    $user->update(['password' => null]);
    expect(fn () => $user->getConnection()->transaction(fn () => $policy->assertRemovalAllowed($user, 'passkey', $passkey->identifier())))->toThrow(AuthException::class);
});

it('rejects malformed native credential identifiers with a domain denial', function (string $kind): void {
    $user = $this->user();
    $policy = app(UsableAccountAuthenticationPolicy::class);

    expect(fn () => $user->getConnection()->transaction(fn () => $policy->assertRemovalAllowed($user, $kind, 'foreign')))
        ->toThrow(AuthException::class, 'The credential is unavailable.');
})->with(['passkey', 'social']);

it('uses the persisted identifier when protecting the last usable credential', function (): void {
    config(['nvl-auth.features.passkeys.enabled' => true]);
    $user = $this->user();
    $user->update(['password' => null]);
    $passkey = Passkey::factory()->forSubject($user)->create([
        'id' => '019a4215-e827-72b5-9f91-aaaaaaaaaaaa',
        'subject_type' => $user->getMorphClass(),
    ]);
    $identifier = strtoupper($passkey->identifier());
    $sameCredential = Passkey::query()->whereKey($identifier)->exists();

    expect(fn () => $user->getConnection()->transaction(fn () => app(UsableAccountAuthenticationPolicy::class)->assertRemovalAllowed($user, 'passkey', $identifier)))
        ->toThrow(AuthException::class, $sameCredential ? 'Keep at least one usable primary authentication method.' : 'The credential is unavailable.');
});

it('rejects an in memory credential ownership forgery after locking and rolls back security facts', function (): void {
    config(['nvl-auth.features.passkeys.enabled' => true]);
    $user = $this->user();
    $other = $this->user('other@example.test');
    $foreign = Passkey::factory()->forSubject($other)->create(['subject_type' => $other->getMorphClass()]);
    $forged = clone $foreign;
    $forged->subject_id = (string) $user->getKey();
    $proof = $this->recentGrant($user, RecentAuthenticationPurpose::FactorRemoval)->reveal();
    expect(fn () => app(AuthPasskeys::class)->revoke($user, $forged, $proof, $this->authenticationContext()))->toThrow(AuthException::class);
    expect($foreign->refresh()->revoked_at)->toBeNull();
    $owned = Passkey::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    Event::fake([AccountSecurityChanged::class]);
    expect(fn () => $user->getConnection()->transaction(function () use ($user, $owned, $proof): void {
        app(AuthPasskeys::class)->revoke($user, $owned, $proof, $this->authenticationContext());
        throw new RuntimeException('rollback');
    }))->toThrow(RuntimeException::class, 'rollback');
    expect($owned->refresh()->revoked_at)->toBeNull();
    Event::assertNotDispatched(AccountSecurityChanged::class);
});

it('rechecks native lockout protection after a permissive consumer policy changes inventory', function (): void {
    config(['nvl-auth.features.passkeys.enabled' => true]);
    $user = $this->user();
    $key = Passkey::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    app()->instance(AccountAuthenticationPolicy::class, new class implements AccountAuthenticationPolicy
    {
        public function assertRemovalAllowed(Authenticatable $subject, string $kind, string $credentialId): void
        {
            $subject->update(['password' => null]);
        }
    });
    $proof = $this->recentGrant($user, RecentAuthenticationPurpose::FactorRemoval)->reveal();
    expect(fn () => app(AuthPasskeys::class)->revoke($user, $key, $proof, $this->authenticationContext()))->toThrow(AuthException::class);
    expect($key->refresh()->revoked_at)->toBeNull()->and($user->refresh()->getAuthPassword())->not->toBeNull();
});
