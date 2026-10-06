<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Nvl\Auth\Actions\Authentication\RequestEmailVerificationAction;
use Nvl\Auth\Actions\Authentication\VerifyEmailAction;
use Nvl\Auth\Actions\Invitations\CreateInvitationAction;
use Nvl\Auth\Actions\Passwords\RequestPasswordResetAction;
use Nvl\Auth\Actions\Passwords\ResetPasswordAction;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Data\Mutations\RequestPasswordResetData;
use Nvl\Auth\Data\Mutations\ResetPasswordData;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Services\AuthCommittedAudit;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\OpaqueTokenFactory;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\Services\TenantMembershipAssignments;
use Nvl\Auth\Tests\CommittedDeliveryTestCase;
use Nvl\Auth\ValueObjects\InvitationIssuanceContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\ConnectionCommitCallbacks;
use Nvl\Support\Events\DomainEventDispatcher;
use Nvl\Support\Tenancy\Contracts\TenantBoundary;
use Nvl\Support\Tenancy\Contracts\TenantMembershipAccess;

uses(CommittedDeliveryTestCase::class);

it('emits verification data without sending and marks the host email verified', function (): void {
    config()->set('nvl-auth.features.email_verification.enabled', true);
    $user = $this->user();
    Event::fake([AuthDeliveryRequested::class]);
    app()->forgetInstance(DomainEventDispatcher::class);
    $connection = $user->getConnection();
    expect($connection->transactionLevel())->toBe(0);
    $connection->beginTransaction();

    try {
        app(RequestEmailVerificationAction::class)->execute($user, 'en');
        Event::assertNotDispatched(AuthDeliveryRequested::class);
        $connection->commit();
    } finally {
        if ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }
    }

    Event::assertDispatched(AuthDeliveryRequested::class, function (AuthDeliveryRequested $event) use ($user): bool {
        return $event->request->recipient === $user->email
            && $event->request->payload['subject_id'] === (string) $user->getKey();
    });

    expect(app(VerifyEmailAction::class)->execute($user))->toBeTrue()
        ->and($user->refresh()->hasVerifiedEmail())->toBeTrue()
        ->and(app(VerifyEmailAction::class)->execute($user))->toBeFalse();
});

it('uses laravel password broker storage and emits delivery instead of notifications', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    app()->forgetInstance(DomainEventDispatcher::class);
    $user = $this->user();
    $connection = $user->getConnection();
    expect($connection->transactionLevel())->toBe(0);
    $connection->beginTransaction();
    try {
        app(RequestPasswordResetAction::class)->execute(new RequestPasswordResetData($user->email));
        Event::assertNotDispatched(AuthDeliveryRequested::class);
        $connection->commit();
    } finally {
        if ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }
    }
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0] ?? null;

    expect($event)->toBeInstanceOf(AuthDeliveryRequested::class)
        ->and($event->request->payload['token'])->toBeString();

    app(ResetPasswordAction::class)->execute(
        new ResetPasswordData(
            $user->email,
            $event->request->payload['token'],
            'new-secure-password',
            'new-secure-password',
        )
    );

    expect(Hash::check('new-secure-password', $user->refresh()->password))->toBeTrue();
});

it('uses the original directly supplied invitation audit recorder after the owning commit', function (): void {
    config()->set('nvl-auth.features.invitations.enabled', true);
    Event::fake([AuthDeliveryRequested::class]);
    app()->forgetInstance(DomainEventDispatcher::class);
    $originalRecorder = new class implements AuthAuditRecorder
    {
        /** @var list<string> */
        public array $actions = [];

        /** @param array<string, mixed> $metadata */
        public function record(
            string $action,
            string $outcome = 'success',
            ?SubjectReference $subject = null,
            ?Authenticatable $actor = null,
            ?string $clientId = null,
            array $metadata = [],
        ): ?object {
            $this->actions[] = $action;

            return null;
        }
    };
    $adapterRecorder = clone $originalRecorder;
    $adapter = new AuthCommittedAudit($adapterRecorder, app(ConnectionCommitCallbacks::class));
    $action = new CreateInvitationAction(
        features: app(FeatureGate::class),
        configuration: app(AuthConfiguration::class),
        tokens: app(OpaqueTokenFactory::class),
        hasher: app(SecretHasher::class),
        authorization: app(ManagementAuthorizer::class),
        pipeline: app(AuthPipeline::class),
        audits: $originalRecorder,
        boundary: app(TenantBoundary::class),
        membershipAccess: app(TenantMembershipAccess::class),
        assignments: app(TenantMembershipAssignments::class),
        committedAudits: $adapter,
        domainEvents: app(DomainEventDispatcher::class),
    );
    $connection = app('db')->connection();
    expect($connection->transactionLevel())->toBe(0);
    $connection->beginTransaction();

    try {
        $issued = $action->execute(
            new StoreInvitationData('direct-recorder@example.test'),
            context: new InvitationIssuanceContext(actorlessAuthorized: true),
        );
        expect($issued->invitation->getConnection())->toBe($connection)
            ->and($originalRecorder->actions)->toBe([])
            ->and($adapterRecorder->actions)->toBe([]);
        Event::assertNotDispatched(AuthDeliveryRequested::class);
        $connection->commit();
    } finally {
        if ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }
    }

    expect($originalRecorder->actions)->toBe(['invitation.issued'])
        ->and($adapterRecorder->actions)->toBe([]);
    Event::assertDispatchedTimes(AuthDeliveryRequested::class, 1);
});
