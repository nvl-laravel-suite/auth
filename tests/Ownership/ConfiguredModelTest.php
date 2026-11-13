<?php

declare(strict_types=1);

use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthMemberships;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\AuthRoles;
use Nvl\Auth\Services\AuthTokens;
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
use Nvl\Ownership\Tests\Fixtures\OptsIntoAdoptedSchemaReuse;
use Nvl\Support\Ownership\Exceptions\OwnershipConfigurationInvalid;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;

uses(ConfiguredOwnerScopeTestCase::class, OptsIntoAdoptedSchemaReuse::class);

it('rejects a model replacement change after the ownership graph has been adopted', function (): void {
    $this->withFixtureConfiguration(['nvl-auth.features.memberships.models.membership' => OwnerMembership::class], function (): void {
        expect(fn () => app(AuthModelRegistry::class)->ownerMembershipClass())->toThrow(OwnershipConfigurationInvalid::class);
    });
});

it('uses configured membership role token and principal subclasses throughout native workflows', function (): void {
    $user = User::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($user): void {
        $membership = app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'configured-workflows'), SubjectReference::fromAuthenticatable($user));
        expect($membership)->toBeInstanceOf(ConfiguredOwnerMembership::class)
            ->and($membership->getTable())->toBe('host_owner_memberships');
        $role = app(AuthRoles::class)->create($user, ['name' => 'configured-editor']);
        $token = app(AuthTokens::class)->create($user, ['name' => 'configured-token', 'abilities' => ['profile:read']]);
        expect($role)->toBeInstanceOf(ConfiguredOwnerRole::class)
            ->and(app(UserLocator::class)->find($user->id))->toBeInstanceOf(ConfiguredOwnerUser::class)
            ->and($token->token['id'])->toBeString()
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
