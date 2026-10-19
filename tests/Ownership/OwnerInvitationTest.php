<?php

declare(strict_types=1);

use Nvl\Auth\Actions\Invitations\AcceptInvitationAction;
use Nvl\Auth\Actions\Invitations\CreateInvitationAction;
use Nvl\Auth\Actions\Invitations\PreviewInvitationAction;
use Nvl\Auth\Actions\Invitations\RegisterInvitationAction;
use Nvl\Auth\Actions\Rbac\CreateRoleAction;
use Nvl\Auth\Data\Mutations\AcceptInvitationData;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Data\Mutations\StoreRoleData;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Models\User;
use Nvl\Auth\Ownership\AuthOwnerAccess;
use Nvl\Auth\Services\OwnerMemberships;
use Nvl\Auth\Tests\OwnerScopeTestCase;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Ownership\Contracts\OwnerAccess;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\Enums\OwnershipContextMode;

uses(OwnerScopeTestCase::class);

it('accepts an owner invitation only for its verified recipient and canonical role grants', function (): void {
    $inviter = User::factory()->create();
    $recipient = User::factory()->create();
    $outsider = User::factory()->create();
    $issued = app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($inviter, $recipient) {
        app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'invitation'), SubjectReference::fromAuthenticatable($inviter));
        $role = app(CreateRoleAction::class)->execute($inviter, new StoreRoleData('invited-editor'));

        return app(CreateInvitationAction::class)->execute(new StoreInvitationData($recipient->email, roles: [$role->id]), $inviter);
    });
    $this->app->bind(OwnerAccess::class, AuthOwnerAccess::class);
    expect(app(PreviewInvitationAction::class)->execute($issued->token)->recipient)->toBe($recipient->email);
    expect(fn () => app(AcceptInvitationAction::class)->execute($issued->token, $outsider))->toThrow(AuthException::class);
    $accepted = app(AcceptInvitationAction::class)->execute($issued->token, $recipient);
    expect($accepted->accepted_by_id)->toBe($recipient->id)
        ->and(fn () => app(AcceptInvitationAction::class)->execute($issued->token, $recipient))->toThrow(AuthException::class)
        ->and(app(OwnershipContext::class)->snapshot()->mode)->toBe(OwnershipContextMode::Unresolved);
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), $recipient, function () use ($recipient): void {
        expect($recipient->fresh()->hasRole('invited-editor'))->toBeTrue()
            ->and(OwnerMembership::query()->where('subject_id', $recipient->id)->count())->toBe(1);
    });
    expect(fn () => app(OwnershipRunner::class)->run(Company::query()->findOrFail(8), $recipient, static fn () => true))->toThrow(AuthException::class);
});

it('registers an invited new identity atomically and rejects replay', function (): void {
    $inviter = User::factory()->create();
    $issued = app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($inviter) {
        app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'registration'), SubjectReference::fromAuthenticatable($inviter));

        return app(CreateInvitationAction::class)->execute(new StoreInvitationData('new-native@example.test'), $inviter);
    });
    $this->app->bind(OwnerAccess::class, AuthOwnerAccess::class);
    $input = new AcceptInvitationData(token: $issued->token, name: 'New Native', password: 'correct-password', passwordConfirmation: 'correct-password');
    $registered = app(RegisterInvitationAction::class)->execute($input);
    expect($registered->subject->getAuthIdentifier())->not->toBe($inviter->id)
        ->and($registered->invitation->accepted_by_id)->toBe($registered->subject->getAuthIdentifier())
        ->and(User::query()->where('email', 'new-native@example.test')->count())->toBe(1)
        ->and(fn () => app(RegisterInvitationAction::class)->execute($input))->toThrow(AuthException::class);
});

it('requires verified authentication before registration can reuse an existing principal', function (): void {
    $inviter = User::factory()->create();
    $recipient = User::factory()->create();
    $issued = app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($inviter, $recipient) {
        app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'existing-registration'), SubjectReference::fromAuthenticatable($inviter));

        return app(CreateInvitationAction::class)->execute(new StoreInvitationData($recipient->email), $inviter);
    });
    $this->app->bind(OwnerAccess::class, AuthOwnerAccess::class);
    $input = new AcceptInvitationData(token: $issued->token, name: 'Existing', password: 'correct-password', passwordConfirmation: 'correct-password');
    expect(fn () => app(RegisterInvitationAction::class)->execute($input))->toThrow(AuthException::class);
    $accepted = app(RegisterInvitationAction::class)->execute($input, $recipient);
    expect($accepted->subject->getAuthIdentifier())->toBe($recipient->id)
        ->and(User::query()->where('email', $recipient->email)->count())->toBe(1);
});
