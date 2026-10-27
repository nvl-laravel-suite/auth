<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Validation\ValidationException;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\PasswordPolicy;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Services\AuthUsers;

beforeEach(function (): void {
    Event::fake([AuthDeliveryRequested::class]);
});

it('rejects a stale password after a broker reset for confirmation and replacement', function (): void {
    $user = $this->user('stale-password@example.test');
    $stale = $user->fresh();
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0];
    app(AuthPasswords::class)->reset(['identifier' => $user->email, 'token' => $event->request->payload['token'], 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']);

    expect(fn () => app(AuthPasswords::class)->confirm($stale, ['password' => 'correct-password'], app('session')->driver()))->toThrow(AuthException::class)
        ->and(fn () => app(AuthPasswords::class)->update($stale, ['currentPassword' => 'correct-password', 'password' => 'new-password-123', 'passwordConfirmation' => 'new-password-123']))->toThrow(AuthException::class)
        ->and(Hash::check('replacement-password', $user->fresh()->password))->toBeTrue();
});

it('requires separate authority for credential edits', function (): void {
    $actor = $this->user('management-actor@example.test');
    $user = $this->user('management-subject@example.test');
    app()->instance(AuthManagementAccess::class, new class implements AuthManagementAccess
    {
        public function allows(Authenticatable $actor, string $ability, mixed $target = null): bool
        {
            return $ability === 'nvl.auth.users.update';
        }
    });

    expect(fn () => app(AuthUsers::class)->update($actor, $user, ['password' => 'new-password-123']))->toThrow(AuthException::class);
    expect(fn () => app(AuthUsers::class)->update($actor, $user, ['emailVerified' => true]))->toThrow(AuthException::class);
});

it('clears verification when an administrator changes an email', function (): void {
    $actor = $this->user('email-actor@example.test');
    $user = $this->user('email-subject@example.test');
    $user->forceFill(['email_verified_at' => now()])->save();

    $updated = app(AuthUsers::class)->update($actor, $user, ['email' => 'changed@example.test']);
    expect($updated->email_verified_at)->toBeNull();
});

it('enforces the password policy and bcrypt byte boundary for password changes', function (): void {
    $user = $this->user('password-policy@example.test');
    $update = fn (string $password) => app(AuthPasswords::class)->update($user, ['currentPassword' => 'correct-password', 'password' => $password, 'passwordConfirmation' => $password]);
    expect(fn () => $update('12345678901'))->toThrow(ValidationException::class)
        ->and(fn () => $update(str_repeat('x', 73)))->toThrow(ValidationException::class);
    $update('123456789012');
    expect(Hash::check('123456789012', $user->fresh()->password))->toBeTrue();
});

it('keeps the bcrypt byte limit with a replacement policy', function (): void {
    app()->instance(PasswordPolicy::class, new class implements PasswordPolicy
    {
        public function rules(): array
        {
            return ['min:1'];
        }
    });
    $user = $this->user('replacement-policy@example.test');
    $change = fn (string $password) => app(AuthPasswords::class)->update($user, ['currentPassword' => 'correct-password', 'password' => $password, 'passwordConfirmation' => $password]);
    expect(fn () => $change(str_repeat('😀', 19)))->toThrow(ValidationException::class);
    $change(str_repeat('😀', 18));
    expect(Hash::check(str_repeat('😀', 18), $user->fresh()->password))->toBeTrue();
});

it('rejects stale account deletion after a broker reset', function (): void {
    $user = $this->user('stale-delete@example.test');
    $stale = $user->fresh();
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0];
    app(AuthPasswords::class)->reset(['identifier' => $user->email, 'token' => $event->request->payload['token'], 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']);
    expect(fn () => app(AuthUsers::class)->deleteOwnAccount($stale, ['currentPassword' => 'correct-password'], auth()->guard('web'), app('session')->driver()))->toThrow(AuthException::class)
        ->and($user->fresh()->trashed())->toBeFalse();
});

it('passes the locked canonical principal to an injected updater and rotates remember credentials', function (): void {
    $user = $this->user('custom-updater@example.test');
    $user->forceFill(['remember_token' => 'original-remember'])->save();
    $stale = $user->fresh();
    $user->forceFill(['name' => 'Canonical name'])->save();
    $stale->name = 'Untrusted name';
    $updater = new class implements PasswordUpdater
    {
        public ?string $seenName = null;

        public function update(CanResetPassword $subject, #[SensitiveParameter] string $password): void
        {
            $this->seenName = $subject->name;
            $subject->forceFill(['password' => Hash::make($password)])->save();
        }
    };
    app()->instance(PasswordUpdater::class, $updater);
    app(AuthPasswords::class)->update($stale, ['currentPassword' => 'correct-password', 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']);
    expect($updater->seenName)->toBe('Canonical name')
        ->and($user->fresh()->remember_token)->not->toBe('original-remember')
        ->and(Hash::check('replacement-password', $user->fresh()->password))->toBeTrue();
});

it('continues to authenticate an existing short password', function (): void {
    $user = $this->user('legacy-short-password@example.test');
    $user->forceFill(['password' => Hash::make('short123')])->save();
    $authenticated = app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'short123'], [], auth()->guard('web'), app('session')->driver());
    expect($authenticated->getAuthIdentifier())->toBe($user->getAuthIdentifier());
});

it('accepts 72 ASCII bytes and rejects 73 for bcrypt', function (): void {
    $user = $this->user('ascii-boundary@example.test');
    $submit = fn (string $password) => app(AuthPasswords::class)->update($user, ['currentPassword' => 'correct-password', 'password' => $password, 'passwordConfirmation' => $password]);
    expect(fn () => $submit(str_repeat('a', 73)))->toThrow(ValidationException::class);
    $submit(str_repeat('a', 72));
    expect(Hash::check(str_repeat('a', 72), $user->fresh()->password))->toBeTrue();
});

it('allows argon passwords beyond 72 bytes while retaining the input limit', function (): void {
    $user = $this->user('argon-boundary@example.test');
    config()->set('hashing.driver', 'argon2id');
    config()->set('hashing.argon', ['memory' => 1024, 'time' => 1, 'threads' => 1]);
    $argon = app('hash')->driver('argon2id');
    $user->forceFill(['password' => $argon->make('correct-password')])->save();
    app()->instance(Hasher::class, $argon);
    $submit = fn (string $password) => app(AuthPasswords::class)->update($user, ['currentPassword' => 'correct-password', 'password' => $password, 'passwordConfirmation' => $password]);
    expect(fn () => $submit(str_repeat('a', 4097)))->toThrow(ValidationException::class);
    $submit(str_repeat('a', 4096));
    expect($argon->check(str_repeat('a', 4096), $user->fresh()->password))->toBeTrue();
});

it('requires credential authority for explicit password removal', function (): void {
    $actor = $this->user('remove-actor@example.test');
    $user = $this->user('remove-target@example.test');
    $user->forceFill(['remember_token' => 'before-removal'])->save();
    $access = new class implements AuthManagementAccess
    {
        public bool $credentials = false;

        public function allows(Authenticatable $actor, string $ability, mixed $target = null): bool
        {
            return $ability === 'nvl.auth.users.update' || ($this->credentials && $ability === 'nvl.auth.users.manageCredentials');
        }
    };
    app()->instance(AuthManagementAccess::class, $access);
    expect(fn () => app(AuthUsers::class)->update($actor, $user, ['password' => null]))->toThrow(AuthException::class)
        ->and(Hash::check('correct-password', $user->fresh()->password))->toBeTrue();
    $access->credentials = true;
    $updated = app(AuthUsers::class)->update($actor, $user, ['password' => null]);
    expect($updated->password)->toBeNull()->and($updated->remember_token)->not->toBe('before-removal');
});

it('enforces the minimum on each new password operation', function (string $path): void {
    $actor = $this->user('policy-actor@example.test');
    $user = $this->user('policy-target@example.test');
    $service = app(AuthPasswords::class);
    $token = null;
    if ($path === 'reset') {
        $service->requestReset(['identifier' => $user->email]);
        $token = Event::dispatched(AuthDeliveryRequested::class)->first()[0]->request->payload['token'];
    }
    if ($path === 'invitation') {
        config()->set('nvl-auth.features.invitations.enabled', true);
        $issued = app(AuthInvitations::class)->create(['recipient' => 'policy-invitee@example.test'], $actor);
        $token = $issued['token'];
    }
    $submit = function (string $password) use ($actor, $user, $path, $service, $token) {
        return match ($path) {
            'reset' => $service->reset(['identifier' => $user->email, 'token' => $token, 'password' => $password, 'passwordConfirmation' => $password]),
            'update' => $service->update($user, ['currentPassword' => 'correct-password', 'password' => $password, 'passwordConfirmation' => $password]),
            'managed_create' => app(AuthUsers::class)->create($actor, ['name' => 'New user', 'email' => 'new-policy@example.test', 'password' => $password]),
            'managed_update' => app(AuthUsers::class)->update($actor, $user, ['password' => $password]),
            'invitation' => app(AuthInvitations::class)->register(['token' => $token, 'name' => 'Invited user', 'password' => $password, 'passwordConfirmation' => $password]),
        };
    };
    expect(fn () => $submit('12345678901'))->toThrow(ValidationException::class);
    $result = $submit('123456789012');
    $principal = match ($path) {
        'managed_create', 'managed_update' => $result,
        'invitation' => $result['subject'],
        default => $user->fresh(),
    };
    expect(Hash::check('123456789012', $principal->password))->toBeTrue();
})->with(['reset', 'update', 'managed_create', 'managed_update', 'invitation']);

it('composes the configured password alias with an injected updater', function (): void {
    $actor = $this->user('alias-actor@example.test');
    Schema::table($actor->getTable(), function (Blueprint $table): void {
        $table->string('credential_hash')->nullable();
    });
    config()->set('nvl-auth.features.principal_management.settings.attributes.password', 'credential_hash');
    app()->forgetInstance(PrincipalAttributeMapper::class);
    $updater = new class implements PasswordUpdater
    {
        public array $seen = [];

        public function update(CanResetPassword $subject, #[SensitiveParameter] string $password): void
        {
            $this->seen[] = [$subject::class, $subject->getAuthPasswordName(), $subject->name];
            $subject->forceFill([$subject->getAuthPasswordName() => Hash::make($password)])->save();
        }
    };
    app()->instance(PasswordUpdater::class, $updater);
    $user = app(AuthUsers::class)->create($actor, ['name' => 'Aliased User', 'email' => 'alias-target@example.test', 'password' => 'first-password-123']);
    expect(Hash::check('first-password-123', $user->credential_hash))->toBeTrue()
        ->and($user->getRawOriginal('password'))->toBeNull();
    $stale = $user->fresh();
    $user->forceFill(['name' => 'Canonical alias'])->save();
    $stale->name = 'Dirty alias';
    $updated = app(AuthUsers::class)->update($actor, $stale, ['password' => 'second-password-123']);
    expect($updater->seen)->toHaveCount(2)
        ->and($updater->seen[1])->toBe([$user::class, 'credential_hash', 'Canonical alias'])
        ->and(Hash::check('second-password-123', $updated->credential_hash))->toBeTrue();
    $removed = app(AuthUsers::class)->update($actor, $updated, ['password' => null]);
    expect($removed->credential_hash)->toBeNull()->and($updater->seen)->toHaveCount(2);
    config()->set('nvl-auth.features.invitations.enabled', true);
    $invitation = app(AuthInvitations::class)->create(['recipient' => 'alias-invite@example.test'], $actor);
    $registered = app(AuthInvitations::class)->register(['token' => $invitation['token'], 'name' => 'Aliased Invitee', 'password' => 'invite-password-123', 'passwordConfirmation' => 'invite-password-123']);
    expect($updater->seen)->toHaveCount(3)
        ->and($updater->seen[2][1])->toBe('credential_hash')
        ->and(Hash::check('invite-password-123', $registered['subject']->credential_hash))->toBeTrue()
        ->and($registered['subject']->getRawOriginal('password'))->toBeNull();
});

it('keeps submitted passwords out of raw and decrypted audit facts', function (): void {
    $actor = $this->user('audit-actor@example.test');
    $user = $this->user('audit-target@example.test');
    $secrets = ['create-private-password', 'update-private-password', 'reset-private-password', 'invite-private-password', 'self-private-password'];
    app(AuthUsers::class)->create($actor, ['name' => 'Audit new', 'email' => 'audit-new@example.test', 'password' => $secrets[0]]);
    app(AuthUsers::class)->update($actor, $user, ['password' => $secrets[1]]);
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
    $token = Event::dispatched(AuthDeliveryRequested::class)->first()[0]->request->payload['token'];
    app(AuthPasswords::class)->reset(['identifier' => $user->email, 'token' => $token, 'password' => $secrets[2], 'passwordConfirmation' => $secrets[2]]);
    app(AuthPasswords::class)->update($user, ['currentPassword' => $secrets[2], 'password' => $secrets[4], 'passwordConfirmation' => $secrets[4]]);
    config()->set('nvl-auth.features.invitations.enabled', true);
    $invitation = app(AuthInvitations::class)->create(['recipient' => 'audit-invite@example.test'], $actor);
    app(AuthInvitations::class)->register(['token' => $invitation['token'], 'name' => 'Audit invited', 'password' => $secrets[3], 'passwordConfirmation' => $secrets[3]]);
    $audits = AuthAudit::query()->get();
    expect($audits->pluck('action')->all())->toContain('user.created', 'user.updated', 'password.reset', 'password.updated', 'invitation.accepted');
    foreach ($audits as $audit) {
        $raw = json_encode($audit->getRawOriginal(), JSON_THROW_ON_ERROR);
        $decrypted = json_encode([$audit->metadata, $audit->ip_address, $audit->user_agent, $audit->action, $audit->request_id], JSON_THROW_ON_ERROR);
        foreach ($secrets as $secret) {
            expect($raw)->not->toContain($secret)->and($decrypted)->not->toContain($secret);
        }
    }
});
