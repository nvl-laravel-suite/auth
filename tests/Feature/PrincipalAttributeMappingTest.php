<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Actions\Authentication\LoginAction;
use Nvl\Auth\Actions\Users\CreateUserAction;
use Nvl\Auth\Actions\Users\SetUserActiveAction;
use Nvl\Auth\Actions\Users\UpdateProfileAction;
use Nvl\Auth\Actions\Users\UpdateUserAction;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Data\Mutations\LoginData;
use Nvl\Auth\Data\Mutations\StoreUserData;
use Nvl\Auth\Data\Mutations\UpdateProfileData;
use Nvl\Auth\Data\Mutations\UpdateUserData;
use Nvl\Auth\Data\Mutations\UpdateUserStatusData;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Tests\Fixtures\MappedPrincipal;
use Nvl\Auth\Tests\Fixtures\MappedPrincipalProfile;

beforeEach(function (): void {
    Schema::create('mapped_principals', function (Blueprint $table): void {
        $table->uuid('id')->primary();
        $table->string('name');
        $table->string('auth_email')->unique();
        $table->timestamp('email_verified_at')->nullable();
        $table->string('password')->nullable();
        $table->boolean('active')->default(true);
        $table->string('locale')->default('en');
        $table->string('timezone')->default('UTC');
        $table->json('auth_profile')->nullable();
        $table->json('auth_preferences')->nullable();
        $table->timestamp('last_login_at')->nullable();
        $table->text('last_login_ip')->nullable();
        $table->timestamp('locked_until')->nullable();
        $table->rememberToken();
        $table->timestamps();
        $table->softDeletes();
    });
    Schema::create('mapped_principal_profiles', function (Blueprint $table): void {
        $table->id();
        $table->uuid('user_id')->unique();
        $table->string('label');
        $table->timestamps();
    });
    config()->set('nvl-auth.tables.users', 'mapped_principals');
    config()->set('nvl-auth.features.principal_management.models.user', MappedPrincipal::class);
    config()->set('auth.providers.users.model', MappedPrincipal::class);
    config()->set('nvl-auth.features.principal_management.settings.attributes.email', 'auth_email');
    config()->set('nvl-auth.features.principal_management.settings.attributes.active', 'active');
    config()->set('nvl-auth.features.principal_management.settings.attributes.profile', 'auth_profile');
    config()->set('nvl-auth.features.principal_management.settings.attributes.preferences', 'auth_preferences');
    app()->forgetInstance(AuthModelRegistry::class);
    app()->forgetInstance(PrincipalAttributeMapper::class);
});

it('maps package principal mutations without shadowing a host profile relationship', function (): void {
    $actor = MappedPrincipal::query()->create([
        'name' => 'Mapped Owner',
        'auth_email' => 'mapped.owner@example.test',
        'password' => 'SecurePassword123',
    ]);
    $user = app(CreateUserAction::class)->execute($actor, new StoreUserData(
        name: 'Mapped User',
        email: 'mapped.user@example.test',
        password: 'SecurePassword123',
        profile: ['phone' => '+359000000000'],
        preferences: ['theme' => 'dark'],
    ));
    MappedPrincipalProfile::query()->create([
        'user_id' => $user->getKey(),
        'label' => 'Domain profile',
    ]);

    $updated = app(UpdateProfileAction::class)->execute($user, new UpdateProfileData(
        name: 'Mapped Updated',
        locale: 'bg',
        timezone: 'Europe/Sofia',
        profile: ['phone' => '+359111111111'],
        preferences: ['theme' => 'light'],
    ));
    $updated = app(UpdateUserAction::class)->execute(
        $actor,
        $updated,
        UpdateUserData::validateForUpdate([
            'name' => 'Sparse Update',
        ], (string) $updated->getKey()),
    );
    $updated = app(UpdateProfileAction::class)->execute(
        $updated,
        UpdateProfileData::validateAndCreate([
            'preferences' => ['theme' => 'system'],
        ]),
    );
    app(SetUserActiveAction::class)->execute($actor, $updated, new UpdateUserStatusData(false));
    $attributes = app(PrincipalAttributeMapper::class);
    $authenticated = app(LoginAction::class)->execute(new LoginData(
        identifier: 'mapped.owner@example.test',
        password: 'SecurePassword123',
        remember: false,
    ));

    expect($updated->fresh()->profile)->toBeInstanceOf(MappedPrincipalProfile::class)
        ->and($updated->getAttribute('auth_profile'))->toBe(['phone' => '+359111111111'])
        ->and($updated->getAttribute('name'))->toBe('Sparse Update')
        ->and($updated->getAttribute('locale'))->toBe('bg')
        ->and($updated->getAttribute('auth_preferences'))->toBe(['theme' => 'system'])
        ->and($attributes->value($updated->fresh(), PrincipalAttribute::Active))->toBeFalse()
        ->and($authenticated->getAuthIdentifier())->toBe($actor->getKey());
});

it('reports mapped attribute and relationship collisions through Doctor', function (): void {
    Schema::table('mapped_principals', function (Blueprint $table): void {
        $table->json('profile')->nullable();
    });
    config()->set('nvl-auth.features.principal_management.settings.attributes.profile', 'profile');
    app()->forgetInstance(PrincipalAttributeMapper::class);

    $this->artisan('nvl:auth:doctor')
        ->expectsOutputToContain('Physical principal columns collide with Eloquent relationships: profile.')
        ->assertFailed();
});
