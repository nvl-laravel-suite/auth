<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Models\User;
use Nvl\Auth\Ownership\AuthOwnerAccess;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Services\AuthMemberships;
use Nvl\Auth\Services\AuthRoles;
use Nvl\Auth\Tests\OwnerScopeTestCase;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Ownership\Contracts\OwnerAccess;
use Nvl\Ownership\Services\OwnerIdentityResolver;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Ownership\Tests\Fixtures\OptsIntoAdoptedSchemaReuse;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\Enums\OwnershipContextMode;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

uses(OwnerScopeTestCase::class, OptsIntoAdoptedSchemaReuse::class);

beforeEach(function (): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'invitation_only']);
});

it('accepts the verified recipient and canonical role grants in only the issuing owner', function (): void {
    $inviter = User::factory()->create();
    $recipient = User::factory()->create();
    $outsider = User::factory()->create();
    $company = Company::query()->findOrFail(7);
    $foreign = Company::query()->findOrFail(8);
    $resolver = app(OwnerIdentityResolver::class);
    $owner = $resolver->reference($company);
    $otherOwner = $resolver->reference($foreign);
    $actor = Actor::query()->findOrFail(1);
    $runner = app(OwnershipRunner::class);
    $issued = $runner->run($company, $actor, function () use ($inviter, $recipient) {
        app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'invitation'), SubjectReference::fromAuthenticatable($inviter));
        $role = app(AuthRoles::class)->create($inviter, ['name' => 'invited-editor']);

        return app(AuthInvitations::class)->create(['recipient' => $recipient->email, 'roles' => [$role->id]], $inviter);
    });
    $other = $runner->run($foreign, $actor, function () use ($inviter, $recipient) {
        app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'other-invitation'), SubjectReference::fromAuthenticatable($inviter));

        return app(AuthInvitations::class)->create(['recipient' => $recipient->email], $inviter);
    });
    $this->app->bind(OwnerAccess::class, AuthOwnerAccess::class);
    $preview = app(AuthInvitations::class)->preview($issued['token']);
    $otherPreview = app(AuthInvitations::class)->preview($other['token']);
    expect($preview->recipient)->toBe($recipient->email)
        ->and($issued['invitation']->owner_scope_key)->toBe($owner->scopeKey())
        ->and($other['invitation']->owner_scope_key)->toBe($otherOwner->scopeKey())
        ->and(OwnerReference::fromJson($preview->owner_reference)->scopeKey())->toBe($owner->scopeKey())
        ->and(OwnerReference::fromJson($otherPreview->owner_reference)->scopeKey())->toBe($otherOwner->scopeKey())
        ->and(fn () => app(AuthInvitations::class)->preview('wrong-token'))->toThrow(AuthException::class);
    expect(fn () => app(AuthInvitations::class)->accept($issued['token'], $outsider))->toThrow(AuthException::class);
    $invitation = $issued['invitation'];
    $persisted = $invitation->getConnection()->table($invitation->getTable())
        ->where($invitation->getKeyName(), $invitation->getKey())->sole(['accepted_at']);
    expect($persisted->accepted_at)->toBeNull();
    $accepted = app(AuthInvitations::class)->accept($issued['token'], $recipient);
    expect($accepted->accepted_by_id)->toBe($recipient->id)
        ->and($accepted->accepted_at)->not->toBeNull()
        ->and(fn () => app(AuthInvitations::class)->accept($issued['token'], $recipient))->toThrow(AuthException::class)
        ->and(app(OwnershipContext::class)->snapshot()->mode)->toBe(OwnershipContextMode::Unresolved);
    $runner->run($company, $recipient, function () use ($recipient): void {
        expect($recipient->fresh()->hasRole('invited-editor'))->toBeTrue()
            ->and(OwnerMembership::query()->where('subject_id', $recipient->id)->count())->toBe(1);
    });
    expect(DB::table('nvl_auth_owner_memberships')->where('owner_scope_key', $otherOwner->scopeKey())
        ->where('subject_id', $recipient->id)->exists())->toBeFalse()
        ->and(fn () => $runner->run($foreign, $recipient, static fn () => true))->toThrow(AuthException::class);

    $runner->run($foreign, $inviter, fn () => $other['invitation']->forceFill(['revoked_at' => now()])->save());
    expect(fn () => app(AuthInvitations::class)->preview($other['token']))->toThrow(AuthException::class);
});

it('registers an invited new identity atomically and rejects replay', function (): void {
    $inviter = User::factory()->create();
    $issued = app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($inviter) {
        app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'registration'), SubjectReference::fromAuthenticatable($inviter));

        return app(AuthInvitations::class)->create(['recipient' => 'new-native@example.test'], $inviter);
    });
    $this->app->bind(OwnerAccess::class, AuthOwnerAccess::class);
    $input = ['token' => $issued['token'], 'name' => 'New Native', 'password' => 'correct-password', 'passwordConfirmation' => 'correct-password'];
    $registered = app(AuthInvitations::class)->register($input);
    expect($registered['subject']->getAuthIdentifier())->not->toBe($inviter->id)
        ->and($registered['invitation']->accepted_by_id)->toBe($registered['subject']->getAuthIdentifier())
        ->and(User::query()->where('email', 'new-native@example.test')->count())->toBe(1)
        ->and(fn () => app(AuthInvitations::class)->register($input))->toThrow(AuthException::class);
});

it('requires verified authentication before registration can reuse an existing principal', function (): void {
    $inviter = User::factory()->create();
    $recipient = User::factory()->create();
    $issued = app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($inviter, $recipient) {
        app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'existing-registration'), SubjectReference::fromAuthenticatable($inviter));

        return app(AuthInvitations::class)->create(['recipient' => $recipient->email], $inviter);
    });
    $this->app->bind(OwnerAccess::class, AuthOwnerAccess::class);
    $input = ['token' => $issued['token'], 'name' => 'Existing', 'password' => 'correct-password', 'passwordConfirmation' => 'correct-password'];
    expect(fn () => app(AuthInvitations::class)->register($input))->toThrow(AuthException::class);
    $accepted = app(AuthInvitations::class)->register($input, $recipient);
    expect($accepted['subject']->getAuthIdentifier())->toBe($recipient->id)
        ->and(User::query()->where('email', $recipient->email)->count())->toBe(1);
});

it('refuses owner invitation grants when the issuer cannot manage member access', function (): void {
    $inviter = User::factory()->create();
    $recipient = User::factory()->create();
    $issued = app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($inviter, $recipient) {
        app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'invitation-grants'), SubjectReference::fromAuthenticatable($inviter));
        $role = app(AuthRoles::class)->create($inviter, ['name' => 'invited-admin']);

        return app(AuthInvitations::class)->create(['recipient' => $recipient->email, 'roles' => [$role->id]], $inviter);
    });
    $this->app->bind(OwnerAccess::class, AuthOwnerAccess::class);
    $this->app->bind(AuthManagementAccess::class, static fn () => new class implements AuthManagementAccess
    {
        public function allows(Authenticatable $actor, string $ability, mixed $target = null): bool
        {
            return $ability !== 'nvl.auth.memberships.manageAccess';
        }
    });

    expect(fn () => app(AuthInvitations::class)->accept($issued['token'], $recipient))->toThrow(AuthException::class, 'not authorized')
        ->and(fn () => app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), $recipient, static fn () => true))->toThrow(AuthException::class);
});
