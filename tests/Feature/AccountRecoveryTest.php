<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Services\AuthAccountRecovery;
use Nvl\Auth\Tests\Fixtures\AllowAllManagementAccess;

it('requires explicit recovery authority and revokes selected credentials atomically', function (): void {
    config(['nvl-auth.features.passkeys.enabled' => true]);
    $actor = $this->user('admin@example.test');
    $user = $this->user();
    $key = Passkey::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    app()->instance(AuthManagementAccess::class, new class implements AuthManagementAccess
    {
        public function allows(Authenticatable $actor, string $ability, mixed $target = null): bool
        {
            return false;
        }
    });
    expect(fn () => app(AuthAccountRecovery::class)->recover($actor, $user, ['reason' => 'Compromised passkey', 'passkeyIds' => [$key->identifier()]]))->toThrow(AuthException::class);
    expect($key->refresh()->revoked_at)->toBeNull();
    app()->instance(AuthManagementAccess::class, new AllowAllManagementAccess);
    app(AuthAccountRecovery::class)->recover($actor, $user, ['reason' => 'Compromised passkey', 'passkeyIds' => [$key->identifier()]]);
    expect($key->refresh()->revoked_at)->not->toBeNull();
});

it('rolls back selected revocations on a foreign credential and refuses primary-less recovery', function (): void {
    config(['nvl-auth.features.passkeys.enabled' => true]);
    $actor = $this->user('admin@example.test');
    $user = $this->user();
    $other = $this->user('other@example.test');
    $owned = Passkey::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $foreign = Passkey::factory()->forSubject($other)->create(['subject_type' => $other->getMorphClass()]);
    expect(fn () => app(AuthAccountRecovery::class)->recover($actor, $user, ['reason' => 'Review compromised credentials', 'passkeyIds' => [$owned->identifier(), $foreign->identifier()]]))->toThrow(AuthException::class);
    expect($owned->refresh()->revoked_at)->toBeNull()->and($foreign->refresh()->revoked_at)->toBeNull();
    $user->update(['password' => null]);
    expect(fn () => app(AuthAccountRecovery::class)->recover($actor, $user, ['reason' => 'Cannot remove final method', 'passkeyIds' => [$owned->identifier()]]))->toThrow(AuthException::class);
    expect($owned->refresh()->revoked_at)->toBeNull();
});
