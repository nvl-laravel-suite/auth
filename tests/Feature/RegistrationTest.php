<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Validation\ValidationException;
use Nvl\Auth\Contracts\RegistrationAdmission;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\RegistrationMethod;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\AuthRegistration;
use Nvl\Auth\Services\AuthSocialAuthentication;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public\RegistrationController;
use Nvl\Auth\Tests\Fixtures\ExtensionPrincipal;
use Nvl\Auth\Tests\Fixtures\TestPrincipalExtensionMapper;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProviderFactory;

it('blocks new invited principals in closed registration without blocking existing recipient acceptance', function (): void {
    config(['nvl-auth.features.invitations.enabled' => true, 'nvl-auth.features.registration.enabled' => false, 'nvl-auth.features.registration.settings.mode' => 'closed']);
    $actor = $this->user();
    $service = app(AuthInvitations::class);
    $issued = $service->create(['recipient' => 'new@example.test'], $actor);
    expect(fn () => $service->register(['token' => $issued['token'], 'name' => 'Invited', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123']))
        ->toThrow(AuthException::class);
    expect(User::query()->where('email', 'new@example.test')->exists())->toBeFalse();
    $actor->markEmailAsVerified();
    $existing = $service->create(['recipient' => $actor->email], $actor);
    expect($service->register(['token' => $existing['token'], 'name' => 'Existing', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123'], $actor)['subject']->getKey())->toBe($actor->getKey());
});

it('registers an active unverified canonical principal without signing in or granting access', function (): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open']);
    $user = app(AuthRegistration::class)->register(['name' => 'Signup', 'email' => ' SIGNUP@Example.Test ', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123']);
    expect($user->email)->toBe('signup@example.test')->and($user->is_active)->toBeTrue()
        ->and($user->hasVerifiedEmail())->toBeFalse()->and(auth()->check())->toBeFalse()
        ->and($user->roles()->count())->toBe(0)->and($user->permissions()->count())->toBe(0);
});

it('keeps native registration mode mandatory even with an allowing host policy', function (bool $enabled, string $mode): void {
    config(['nvl-auth.features.registration.enabled' => $enabled, 'nvl-auth.features.registration.settings.mode' => $mode]);
    app()->instance(RegistrationAdmission::class, new class implements RegistrationAdmission
    {
        public function assertAllowed(RegistrationMethod $method, string $normalizedEmail, array $validatedExtensions): void {}
    });
    expect(fn () => app(AuthRegistration::class)->register(['name' => 'No signup', 'email' => 'no@example.test', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123']))->toThrow(AuthException::class);
    expect(User::query()->count())->toBe(0);
})->with([[false, 'open'], [true, 'closed'], [true, 'invitation_only']]);

it('rejects privilege and caller method input before principal writes', function (string $field): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open']);
    expect(fn () => app(AuthRegistration::class)->register(['name' => 'No signup', 'email' => 'no@example.test', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123', $field => true]))->toThrow(InvalidArgumentException::class);
    expect(User::query()->count())->toBe(0);
})->with(['roles', 'permissions', 'owner', 'actor', 'active', 'emailVerified', 'email_identity_hash', 'provider', 'registrationMethod']);

it('returns a stable unavailable conflict for normalized and retained identities', function (bool $deleted): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open']);
    $user = $this->user('duplicate@example.test');
    if ($deleted) {
        $user->delete();
    }
    try {
        app(AuthRegistration::class)->register(['name' => 'Duplicate', 'email' => ' DUPLICATE@Example.Test ', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123']);
        test()->fail('A duplicate registration succeeded.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('registration_unavailable');
    }
    expect(User::withTrashed()->count())->toBe(1);
})->with([false, true]);

it('uses the shared password rules and matching confirmation', function (string $password, string $confirmation): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open']);
    expect(fn () => app(AuthRegistration::class)->register(['name' => 'Rejected', 'email' => 'rejected@example.test', 'password' => $password, 'passwordConfirmation' => $confirmation]))->toThrow(ValidationException::class);
    expect(User::query()->count())->toBe(0);
})->with([['short', 'short'], ['SecurePassword123', 'different-password']]);

it('maps host extensions before transaction-local admission and rolls back host denial', function (): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open', 'nvl-auth.features.principal_management.models.user' => ExtensionPrincipal::class, 'auth.providers.users.model' => ExtensionPrincipal::class, 'nvl-auth.features.principal_management.services.extension_mapper' => TestPrincipalExtensionMapper::class]);
    Schema::table(AuthTables::Users, function (Blueprint $table): void {
        $table->string('job_title')->nullable();
    });
    app()->forgetInstance(AuthModelRegistry::class);
    $admission = new class implements RegistrationAdmission
    {
        public bool $deny = true;

        public function assertAllowed(RegistrationMethod $method, string $normalizedEmail, array $validatedExtensions): void
        {
            expect($method)->toBe(RegistrationMethod::Password)->and($normalizedEmail)->toBe('host@example.test')
                ->and($validatedExtensions)->toBe(['job_title' => 'Engineer'])->and(DB::transactionLevel())->toBeGreaterThan(0);
            if ($this->deny) {
                throw new AuthException('registration_denied', 'Host admission rejected.');
            }
        }
    };
    app()->instance(RegistrationAdmission::class, $admission);
    $data = ['name' => 'Host', 'email' => ' HOST@example.test ', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123', 'extensions' => ['jobTitle' => 'Engineer']];
    expect(fn () => app(AuthRegistration::class)->register($data))->toThrow(AuthException::class, 'Host admission');
    expect(User::query()->count())->toBe(0)->and(AuthAudit::query()->where('action', 'registration.completed')->count())->toBe(0);
    $admission->deny = false;
    $user = app(AuthRegistration::class)->register($data);
    expect($user->job_title)->toBe('Engineer');
});

it('leaves no registration fact when the extension mapper rejects input', function (): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open']);
    expect(fn () => app(AuthRegistration::class)->register(['name' => 'Rejected', 'email' => 'rejected@example.test', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123', 'extensions' => ['unknown' => true]]))->toThrow(InvalidArgumentException::class);
    expect(User::query()->count())->toBe(0)->and(AuthAudit::query()->where('action', 'registration.completed')->count())->toBe(0);
});

it('rechecks mandatory mode after consumer admission before writing', function (): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open']);
    app()->instance(RegistrationAdmission::class, new class implements RegistrationAdmission
    {
        public function assertAllowed(RegistrationMethod $method, string $normalizedEmail, array $validatedExtensions): void
        {
            config()->set('nvl-auth.features.registration.settings.mode', 'closed');
        }
    });
    expect(fn () => app(AuthRegistration::class)->register(['name' => 'Rejected', 'email' => 'rejected@example.test', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123']))->toThrow(AuthException::class);
    expect(User::query()->count())->toBe(0);
});

it('lets the consumer choose neutral HTTP conflict presentation', function (): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open']);
    Route::post('/consumer-signup', RegistrationController::class);
    $data = ['name' => 'Signup', 'email' => 'http@example.test', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123'];
    $this->postJson('/consumer-signup', $data)->assertStatus(202)->assertExactJson(['message' => 'Your registration request was processed.']);
    $this->postJson('/consumer-signup', $data)->assertStatus(202)->assertExactJson(['message' => 'Your registration request was processed.']);
    expect(User::query()->count())->toBe(1)->and(auth()->check())->toBeFalse();
});

it('requires explicit registration after an unknown social callback without provisioning or authenticating', function (): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open', 'nvl-auth.features.social_identities.enabled' => true, 'nvl-auth.features.social_identities.settings.providers.github' => ['scopes' => [], 'parameters' => []]]);
    app()->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory);
    $service = app(AuthSocialAuthentication::class);
    $context = $this->authenticationContext();
    $started = $service->beginLogin('github', $context);
    expect($service->completeLogin('github', $started['intent']->reveal(), $context)['status'])->toBe('registration_required');
    expect(User::query()->count())->toBe(0)->and(SocialIdentity::query()->count())->toBe(0)->and(auth()->check())->toBeFalse();
    $registered = app(AuthRegistration::class)->register(['name' => 'Allowed password', 'email' => 'allowed@example.test', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123']);
    expect($registered->email)->toBe('allowed@example.test');
});

it('requires password capability for public and invited password provisioning', function (): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open', 'nvl-auth.features.password.enabled' => false, 'nvl-auth.features.invitations.enabled' => true]);
    $actor = $this->user();
    $data = ['name' => 'Blocked', 'email' => 'blocked@example.test', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123'];
    expect(fn () => app(AuthRegistration::class)->register($data))->toThrow(AuthException::class);
    $issued = app(AuthInvitations::class)->create(['recipient' => $data['email']], $actor);
    expect(fn () => app(AuthInvitations::class)->register(array_diff_key($data, ['email' => true]) + ['token' => $issued['token']]))->toThrow(AuthException::class);
    expect(User::query()->where('email', $data['email'])->exists())->toBeFalse();
});
