<?php

declare(strict_types=1);

use Nvl\Auth\Actions\ApiTokens\CreateApiTokenAction;
use Nvl\Auth\Actions\Rbac\CreateRoleAction;
use Nvl\Auth\Data\Mutations\ApiTokenData;
use Nvl\Auth\Data\Mutations\StoreRoleData;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\OwnerMemberships;
use Nvl\Auth\Services\UserLocator;
use Nvl\Auth\Tests\ConfiguredOwnerScopeTestCase;
use Nvl\Auth\Tests\Fixtures\ConfiguredOwnerMembership;
use Nvl\Auth\Tests\Fixtures\ConfiguredOwnerRole;
use Nvl\Auth\Tests\Fixtures\ConfiguredOwnerToken;
use Nvl\Auth\Tests\Fixtures\ConfiguredOwnerUser;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Support\Ownership\Exceptions\OwnershipConfigurationInvalid;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;

uses(ConfiguredOwnerScopeTestCase::class);

it('uses the exact configured membership subclass in storage and workflows', function (): void {
    $user = User::factory()->create();
    $membership = app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), fn () => app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'configured'), SubjectReference::fromAuthenticatable($user)));
    expect($membership)->toBeInstanceOf(ConfiguredOwnerMembership::class)
        ->and($membership->getTable())->toBe('host_owner_memberships');
});

it('rejects a model replacement change after the ownership graph has been adopted', function (): void {
    config(['nvl-auth.features.memberships.models.membership' => OwnerMembership::class]);
    expect(fn () => app(AuthModelRegistry::class)->ownerMembershipClass())->toThrow(OwnershipConfigurationInvalid::class);
});

it('uses configured role token and global principal subclasses throughout native workflows', function (): void {
    $user = User::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($user): void {
        app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'configured-workflows'), SubjectReference::fromAuthenticatable($user));
        $role = app(CreateRoleAction::class)->execute($user, new StoreRoleData('configured-editor'));
        $token = app(CreateApiTokenAction::class)->execute($user, new ApiTokenData('configured-token', ['profile:read']));
        expect($role)->toBeInstanceOf(ConfiguredOwnerRole::class)
            ->and(app(UserLocator::class)->find($user->id))->toBeInstanceOf(ConfiguredOwnerUser::class)
            ->and($token->token->id)->toBeString()
            ->and(app(AuthModelRegistry::class)->personalAccessTokenClass())->toBe(ConfiguredOwnerToken::class);
        expect(fn () => Role::query()->get())->toThrow(OwnershipViolation::class);
    });
});

it('creates a configured membership subclass through the inherited package factory', function (): void {
    $user = User::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($user): void {
        $membership = ConfiguredOwnerMembership::factory()->create(['subject_type' => $user->getMorphClass(), 'subject_id' => $user->id]);
        expect($membership)->toBeInstanceOf(ConfiguredOwnerMembership::class)
            ->and($membership->getTable())->toBe('host_owner_memberships');
    });
});
