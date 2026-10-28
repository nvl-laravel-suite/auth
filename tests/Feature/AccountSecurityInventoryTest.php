<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Event;
use Nvl\Auth\Contracts\AccountAuthenticationPolicy;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Events\AccountSecurityChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Services\AuthAccountSecurity;
use Nvl\Auth\Services\AuthPasskeys;
use Nvl\Auth\Services\UsableAccountAuthenticationPolicy;

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
