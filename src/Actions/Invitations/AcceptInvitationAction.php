<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\InvitationRecipientProof;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\InvitationAccepted;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\InvitationTenantBootstrap;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\MembershipOwnerGuard;
use Nvl\Auth\Services\MembershipWriter;
use Nvl\Auth\Services\RbacManager;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\Services\TenantMembershipAssignments;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Tenancy\Services\TenantBoundary;
use Nvl\Tenancy\Services\TenantRunner;
use Nvl\Tenancy\ValueObjects\TenantId;

/**
 * Consumes one invitation and optionally applies its Spatie Permission payload.
 */
final readonly class AcceptInvitationAction
{
    /**
     * Create the invitation acceptance use case.
     */
    public function __construct(
        private FeatureGate $features,
        private SecretHasher $hasher,
        private InvitationRecipientProof $recipientProof,
        private RbacManager $rbac,
        private InvitationTenantBootstrap $bootstrap,
        private TenantRunner $runner,
        private TenantBoundary $boundary,
        private MembershipPrincipalResolver $principals,
        private MembershipOwnerGuard $owners,
        private MembershipWriter $memberships,
        private TenantMembershipAssignments $assignments,
        private TenantMembershipAccess $membershipAccess,
        private ManagementAuthorizer $authorization,
        private AuthPipeline $pipeline,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Consume an invitation for the supplied host subject.
     */
    public function execute(string $token, Authenticatable $subject): Invitation
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Use);
        $reference = SubjectReference::fromAuthenticatable($subject);

        if (config('tenancy.enabled') === true) {
            $tenant = $this->bootstrap->tenantForToken($token);
            if (! $tenant instanceof TenantId) {
                throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
            }

            return $this->runner->run($tenant, fn (): Invitation => $this->accept($token, $subject, $reference, $tenant));
        }

        return $this->pipeline->run(
            'invitation_accepted',
            new AuthPipelineContext('invitation_accepted', subject: $reference),
            function () use ($reference, $subject, $token): Invitation {
                $connection = (new Invitation)->getConnectionName();

                return DB::connection($connection)->transaction(function () use ($reference, $subject, $token): Invitation {
                    /** @var Invitation|null $invitation */
                    $invitation = Invitation::query()
                        ->where('token_hash', $this->hasher->hash('invitation-token', $token))
                        ->lockForUpdate()
                        ->first();

                    if (! $invitation instanceof Invitation || ! $invitation->isUsable()) {
                        throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
                    }

                    $this->recipientProof->assertMatches($invitation, $subject);
                    $roles = is_array($invitation->roles) ? $invitation->roles : [];
                    $permissions = is_array($invitation->permissions) ? $invitation->permissions : [];
                    $this->rbac->assign($subject, $roles, $permissions);
                    $acceptedAt = CarbonImmutable::now();
                    $invitation->forceFill([
                        'active_key' => null,
                        'accepted_by_type' => $reference->type,
                        'accepted_by_id' => $reference->identifier,
                        'accepted_at' => $acceptedAt,
                    ])->save();
                    $this->audits->record(
                        'invitation.accepted',
                        subject: $reference,
                        actor: $subject,
                        metadata: ['invitation_id' => $invitation->identifier()],
                    );
                    InvitationAccepted::dispatch(
                        invitationId: $invitation->identifier(),
                        type: $invitation->type,
                        purpose: $invitation->purpose,
                        subject: $reference,
                        acceptedAt: $invitation->accepted_at,
                    );

                    return $invitation;
                }, 3);
            },
        );
    }

    /** Consume a tenant invitation and enroll its proven recipient atomically. */
    private function accept(
        string $token,
        Authenticatable $subject,
        SubjectReference $reference,
        TenantId $tenant,
    ): Invitation {
        return $this->pipeline->run(
            'invitation_accepted',
            new AuthPipelineContext('invitation_accepted', subject: $reference),
            function () use ($reference, $subject, $tenant, $token): Invitation {
                $connection = (new Invitation)->getConnection()->getName();
                $membershipConnection = (new TenantMembership)->getConnection()->getName();
                if ($connection !== $membershipConnection || $connection !== $this->principals->connectionName()) {
                    throw AuthException::invalidConfiguration(
                        'Tenant invitation acceptance requires invitation, principal, and membership storage on one connection.',
                    );
                }

                return DB::connection($connection)->transaction(function () use ($connection, $reference, $subject, $tenant, $token): Invitation {
                    $candidate = $this->boundary->query(Invitation::query(), 'auth.invitations')
                        ->where('token_hash', $this->hasher->hash('invitation-token', $token))
                        ->first();
                    if (! $candidate instanceof Invitation || ! $candidate->isUsable()) {
                        throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
                    }
                    $this->recipientProof->assertMatches($candidate, $subject);
                    $principal = $this->principals->resolve($reference, true);
                    $this->owners->lock($tenant);
                    /** @var Invitation|null $invitation */
                    $invitation = $this->boundary->query(Invitation::query(), 'auth.invitations')
                        ->whereKey($candidate->getKey())
                        ->lockForUpdate()
                        ->first();
                    if (! $invitation instanceof Invitation || ! $invitation->isUsable()
                        || ! hash_equals($invitation->token_hash, $this->hasher->hash('invitation-token', $token))) {
                        throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
                    }
                    if (! is_string($invitation->inviter_type) || ! is_string($invitation->inviter_id)) {
                        throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
                    }
                    $inviter = $this->principals->resolve(new SubjectReference(
                        $invitation->inviter_type,
                        $invitation->inviter_id,
                    ), true);
                    $this->membershipAccess->assertMember($inviter, $tenant);
                    $this->authorization->authorize($inviter, 'nvl-auth.invitations.create');

                    $roles = is_array($invitation->roles) ? $invitation->roles : [];
                    $permissions = is_array($invitation->permissions) ? $invitation->permissions : [];
                    $this->assignments->canonicalIdentifiers($roles, $permissions);
                    $membership = $this->memberships->enroll($reference);
                    $this->assignments->sync($principal, $roles, $permissions);
                    $acceptedAt = CarbonImmutable::now();
                    $invitation->forceFill([
                        'active_key' => null,
                        'accepted_by_type' => $reference->type,
                        'accepted_by_id' => $reference->identifier,
                        'accepted_at' => $acceptedAt,
                    ])->save();
                    DB::connection($connection)->afterCommit(function () use ($invitation, $membership, $reference, $subject): void {
                        $this->audits->record(
                            'invitation.accepted',
                            subject: $reference,
                            actor: $subject,
                            metadata: [
                                'invitation_id' => $invitation->identifier(),
                                'membership_id' => $membership->identifier(),
                            ],
                        );
                        InvitationAccepted::dispatch(
                            invitationId: $invitation->identifier(),
                            type: $invitation->type,
                            purpose: $invitation->purpose,
                            subject: $reference,
                            acceptedAt: $invitation->accepted_at,
                        );
                    });

                    return $invitation;
                }, 3);
            },
        );
    }
}
