<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Validation\ValidationException;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\PrincipalExtensionMapper;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\PrincipalMutation;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Services\PrincipalExtensions;
use Nvl\Auth\Tests\Fixtures\ExtensionPrincipal;
use Nvl\Auth\Tests\Fixtures\TestPrincipalExtensionMapper;

beforeEach(function (): void {
    Schema::table(AuthTables::Users, function (Blueprint $table): void {
        $table->string('job_title')->nullable();
        $table->string('phone')->nullable();
        $table->string('unfillable')->nullable();
    });
    config()->set('nvl-auth.features.principal_management.models.user', ExtensionPrincipal::class);
    config()->set('auth.providers.users.model', ExtensionPrincipal::class);
    config()->set('nvl-auth.features.principal_management.services.extension_mapper', TestPrincipalExtensionMapper::class);
    app()->forgetInstance(AuthModelRegistry::class);
    app()->forgetInstance(PrincipalExtensionMapper::class);
});

it('persists bounded host fields through complete management and sparse profile operations', function (): void {
    $actor = $this->user();
    $user = app(AuthUsers::class)->create($actor, ['name' => 'Host', 'email' => 'host@example.test', 'password' => 'SecurePassword123', 'extensions' => ['jobTitle' => 'Engineer', 'phone' => '123']]);
    expect($user)->toBeInstanceOf(ExtensionPrincipal::class)
        ->and($user->job_title)->toBe('Engineer');
    $user = app(AuthUsers::class)->update($actor, $user, ['extensions' => ['jobTitle' => 'Architect']]);
    expect($user->job_title)->toBe('Architect')->and($user->phone)->toBe('123');
    $user = app(AuthUsers::class)->updateProfile($user, ['name' => 'Renamed']);
    expect($user->job_title)->toBe('Architect');
    $user = app(AuthUsers::class)->updateProfile($user, ['extensions' => ['jobTitle' => null]]);
    expect($user->job_title)->toBeNull()->and($user->phone)->toBe('123');
});

it('rejects nonempty extensions by default and resolves a cached host binding without Request', function (): void {
    config()->set('nvl-auth.features.principal_management.services.extension_mapper', null);
    app()->forgetInstance(PrincipalExtensionMapper::class);
    expect(fn () => app(PrincipalExtensions::class)->map(PrincipalMutation::Registration, ['phone' => '123']))
        ->toThrow(InvalidArgumentException::class, 'configured mapper');
    expect(app(PrincipalExtensions::class)->map(PrincipalMutation::Registration, []))->toBe([]);

    $cached = '<?php return '.var_export(['extension_mapper' => TestPrincipalExtensionMapper::class], true).';';
    $path = tempnam(sys_get_temp_dir(), 'nvl-extension-config-');
    try {
        file_put_contents($path, $cached);
        config()->set('nvl-auth.features.principal_management.services', require $path);
        app()->forgetInstance(PrincipalExtensionMapper::class);
        app()->forgetInstance('request');
        expect(app(PrincipalExtensionMapper::class))->toBeInstanceOf(TestPrincipalExtensionMapper::class)
            ->and(app(PrincipalExtensions::class)->map(PrincipalMutation::Registration, ['jobTitle' => 'Host']))->toBe(['job_title' => 'Host']);
    } finally {
        unlink($path);
    }
});

it('rejects protected logical fields and physical aliases before persistence', function (string $field): void {
    config()->set('nvl-auth.features.principal_management.settings.attributes.email_identity_hash', 'host_email_key');
    config()->set('nvl-auth.features.principal_management.settings.attributes.password', 'host_password');
    app()->forgetInstance(PrincipalAttributeMapper::class);
    app()->instance(PrincipalExtensionMapper::class, new class($field) implements PrincipalExtensionMapper
    {
        public function __construct(private string $field) {}

        public function validateAndMap(PrincipalMutation $mutation, array $extensions, ?User $principal = null): array
        {
            return [$this->field => 'changed'];
        }
    });
    expect(fn () => app(PrincipalExtensions::class)->map(PrincipalMutation::Profile, [$field => 'changed']))
        ->toThrow(InvalidArgumentException::class, 'protected')
        ->and(fn () => app(PrincipalExtensions::class)->map(PrincipalMutation::Profile, ['phone' => '123']))
        ->toThrow(InvalidArgumentException::class, 'protected');
})->with(['PASSWORD', 'HOST_PASSWORD', 'EMAIL_IDENTITY_HASH', 'password', 'host_password', 'email_identity_hash', 'host_email_key', 'emailVerified', 'id', 'created_at', 'deleted_at', 'rememberToken', 'owner_id', 'ownership_id', 'security_revision', 'subject_id', 'revision', 'roles', 'permissions', 'is_active']);

it('bounds both sides of extension mapping and rejects non JSON values', function (string $kind, bool $output): void {
    $value = match ($kind) {
        'large' => str_repeat('x', 16384),
        'object' => new stdClass,
        'nan' => NAN,
        'depth' => array_reduce(range(1, 16), static fn ($carry) => ['child' => $carry], 'leaf'),
    };
    app()->instance(PrincipalExtensionMapper::class, new class($value, $output) implements PrincipalExtensionMapper
    {
        public function __construct(private mixed $value, private bool $output) {}

        public function validateAndMap(PrincipalMutation $mutation, array $extensions, ?User $principal = null): array
        {
            return $this->output ? ['phone' => $this->value] : [];
        }
    });
    expect(fn () => app(PrincipalExtensions::class)->map(PrincipalMutation::Profile, $output ? [] : ['phone' => $value]))
        ->toThrow(InvalidArgumentException::class);
})->with(['large', 'object', 'nan', 'depth'])->with([false, true]);

it('enforces fillable and overlap checks even with global unguarding', function (): void {
    app()->instance(PrincipalExtensionMapper::class, new class implements PrincipalExtensionMapper
    {
        public function validateAndMap(PrincipalMutation $mutation, array $extensions, ?User $principal = null): array
        {
            return $extensions;
        }
    });
    User::unguarded(function (): void {
        expect(fn () => app(PrincipalExtensions::class)->map(PrincipalMutation::ManagementUpdate, ['unfillable' => 'unsafe']))
            ->toThrow(InvalidArgumentException::class, 'fillable');
    });
    expect(fn () => app(PrincipalExtensions::class)->map(PrincipalMutation::Registration, ['phone' => '123'], occupiedColumns: ['phone']))
        ->toThrow(InvalidArgumentException::class, 'protected');
});

it('rolls back native principal changes and emits no success when mapping fails', function (): void {
    $actor = $this->user();
    Event::fake([PrincipalChanged::class]);
    $audits = AuthAudit::query()->count();
    $data = ['name' => 'Rejected', 'email' => 'rejected@example.test', 'password' => 'SecurePassword123', 'extensions' => ['jobTitle' => str_repeat('x', 101)]];
    expect(fn () => app(AuthUsers::class)->create($actor, $data))->toThrow(ValidationException::class);
    expect(User::query()->where('email', 'rejected@example.test')->exists())->toBeFalse();
    expect(fn () => app(AuthUsers::class)->updateProfile(ExtensionPrincipal::query()->findOrFail($actor->getKey()), ['name' => 'Changed', 'extensions' => ['unknown' => true]]))->toThrow(InvalidArgumentException::class);
    expect($actor->refresh()->name)->toBe('Test User')->and(AuthAudit::query()->count())->toBe($audits);
    Event::assertNotDispatched(PrincipalChanged::class);
});

it('maps invited principal extensions inside the native acceptance transaction', function (): void {
    config()->set('nvl-auth.features.invitations.enabled', true);
    $actor = $this->user();
    $issued = app(AuthInvitations::class)->create(['recipient' => 'extended.invitee@example.test'], $actor);
    $data = ['token' => $issued['token'], 'name' => 'Invitee', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123'];
    expect(fn () => app(AuthInvitations::class)->register($data + ['extensions' => ['jobTitle' => str_repeat('x', 101)]]))
        ->toThrow(ValidationException::class);
    expect(User::query()->where('email', 'extended.invitee@example.test')->exists())->toBeFalse()
        ->and($issued['invitation']->refresh()->accepted_at)->toBeNull();
    $result = app(AuthInvitations::class)->register($data + ['extensions' => ['jobTitle' => 'Invited']]);
    expect($result['subject']->job_title)->toBe('Invited')->and($result['invitation']->accepted_at)->not->toBeNull();
});
