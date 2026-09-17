<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\InvitationRecipientProof;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Data\Mutations\AcceptInvitationData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Events\InvitationAccepted;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Results\InvitationRegistrationResult;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\InvitationTenantBootstrap;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\MembershipOwnerGuard;
use Nvl\Auth\Services\MembershipWriter;
use Nvl\Auth\Services\RbacManager;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\Services\TenantMembershipAssignments;
use Nvl\Auth\ValueObjects\AuthEventContext;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Tenancy\Enums\TenantContextMode;
use Nvl\Tenancy\Services\TenantBoundary;
use Nvl\Tenancy\Services\TenantRunner;
use Nvl\Tenancy\ValueObjects\TenantId;

/**
 * Creates or resolves a principal and consumes its invitation atomically.
 */
final readonly class RegisterInvitationAction
{
    /** Create the atomic invitation registration use case. */
    public function __construct(
        private FeatureGate $features,
        private SecretHasher $hasher,
        private InvitationSubjectResolver $subjects,
        private InvitationRecipientProof $recipientProof,
        private InvitationTenantBootstrap $bootstrap,
        private RbacManager $rbac,
        private AuthPipeline $pipeline,
        private AuthAuditRecorder $audits,
        private AuthModelRegistry $models,
        private PrincipalAttributeMapper $attributes,
        private TenantRunner $runner,
        private TenantBoundary $boundary,
        private MembershipPrincipalResolver $principals,
        private MembershipOwnerGuard $owners,
        private MembershipWriter $memberships,
        private TenantMembershipAssignments $assignments,
        private TenantMembershipAccess $membershipAccess,
        private ManagementAuthorizer $authorization,
    ) {}

    /** Register the invited subject and return the consumed invitation and subject. */
    public function execute(
        AcceptInvitationData $data,
        ?Authenticatable $authenticatedRecipient = null,
    ): InvitationRegistrationResult {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Use);
        if (config('tenancy.enabled') === true) {
            $tenant = $this->bootstrap->tenantForToken($data->token);
            if (! $tenant instanceof TenantId) {
                throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
            }

            return $this->runner->run(
                $tenant,
                fn (): InvitationRegistrationResult => $this->register($data, $authenticatedRecipient, $tenant),
            );
        }

        return $this->register($data, $authenticatedRecipient);
    }

    /** Perform registration in the already-selected ownership boundary. */
    private function register(
        AcceptInvitationData $data,
        ?Authenticatable $authenticatedRecipient,
        ?TenantId $tenant = null,
    ): InvitationRegistrationResult {
        $connection = (new Invitation)->getConnectionName();
        $principalClass = $this->models->userClass();
        $principalConnection = (new $principalClass)->getConnectionName();

        if ($principalConnection !== $connection) {
            throw AuthException::invalidConfiguration(
                'Invitation registration requires principal and invitation storage on one connection.',
            );
        }

        try {
            return DB::connection($connection)->transaction(function () use ($authenticatedRecipient, $connection, $data, $tenant): InvitationRegistrationResult {
                $query = $tenant instanceof TenantId
                    ? $this->boundary->query(Invitation::query(), 'auth.invitations')
                    : Invitation::query();
                /** @var Invitation|null $invitation */
                $invitation = $query
                    ->where('token_hash', $this->hasher->hash('invitation-token', $data->token))
                    ->lockForUpdate()
                    ->first();

                if (! $invitation instanceof Invitation || ! $invitation->isUsable()) {
                    throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
                }

                $subject = $this->resolveSubject($invitation, $data, $authenticatedRecipient);
                $reference = SubjectReference::fromAuthenticatable($subject);

                return $this->pipeline->run(
                    'invitation_accepted',
                    new AuthPipelineContext('invitation_accepted', [
                        'invitation_id' => $invitation->identifier(),
                        'type' => $invitation->type,
                        'purpose' => $invitation->purpose,
                        'metadata' => $invitation->metadata,
                    ], $reference),
                    function () use ($connection, $invitation, $reference, $subject, $tenant): InvitationRegistrationResult {
                        $roles = is_array($invitation->roles) ? $invitation->roles : [];
                        $permissions = is_array($invitation->permissions) ? $invitation->permissions : [];
                        $membership = null;
                        if ($tenant instanceof TenantId) {
                            $principal = $this->principals->resolve($reference, true);
                            $this->owners->lock($tenant);
                            if (! is_string($invitation->inviter_type) || ! is_string($invitation->inviter_id)) {
                                throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
                            }
                            $inviter = $this->principals->resolve(new SubjectReference(
                                $invitation->inviter_type,
                                $invitation->inviter_id,
                            ), true);
                            $this->membershipAccess->assertMember($inviter, $tenant);
                            $this->authorization->authorize($inviter, 'nvl-auth.invitations.create');
                            $this->assignments->canonicalIdentifiers($roles, $permissions);
                            $membership = $this->memberships->enroll($reference);
                            $this->assignments->sync($principal, $roles, $permissions);
                        } else {
                            $this->rbac->assign($subject, $roles, $permissions);
                        }
                        $acceptedAt = CarbonImmutable::now();
                        $invitation->forceFill([
                            'active_key' => null,
                            'accepted_by_type' => $reference->type,
                            'accepted_by_id' => $reference->identifier,
                            'accepted_at' => $acceptedAt,
                        ])->save();
                        DB::connection($connection)->afterCommit(function () use ($invitation, $membership, $reference, $subject, $tenant): void {
                            $metadata = ['invitation_id' => $invitation->identifier()];
                            if ($membership !== null) {
                                $metadata['membership_id'] = $membership->identifier();
                            }
                            $this->audits->record('invitation.accepted', subject: $reference, actor: $subject, metadata: $metadata);
                            InvitationAccepted::dispatch(
                                invitationId: $invitation->identifier(),
                                type: $invitation->type,
                                purpose: $invitation->purpose,
                                subject: $reference,
                                acceptedAt: $invitation->accepted_at,
                                context: $tenant instanceof TenantId
                                    ? new AuthEventContext(TenantContextMode::Tenant, $tenant)
                                    : null,
                            );
                            PrincipalChanged::dispatch(
                                $reference->identifier,
                                'invitation_registered',
                                context: $tenant instanceof TenantId
                                    ? new AuthEventContext(TenantContextMode::Tenant, $tenant)
                                    : null,
                            );
                        });

                        return new InvitationRegistrationResult($invitation, $subject);
                    },
                );
            }, 3);
        } catch (QueryException $exception) {
            if (in_array($exception->errorInfo[0] ?? null, ['23000', '23505'], true)) {
                throw new AuthException(
                    'invitation_principal_conflict',
                    'The invited principal already exists.',
                    409,
                    previous: $exception,
                );
            }

            throw $exception;
        }
    }

    /** Resolve a new identity or require proof before reusing a global identity. */
    private function resolveSubject(
        Invitation $invitation,
        AcceptInvitationData $data,
        ?Authenticatable $authenticatedRecipient,
    ): Authenticatable {
        $principalClass = $this->models->userClass();
        /** @var Authenticatable|null $existing */
        $existing = $principalClass::query()
            ->where($this->attributes->column(PrincipalAttribute::Email), mb_strtolower(trim($invitation->recipient)))
            ->first();
        if ($existing instanceof Authenticatable) {
            if (! $authenticatedRecipient instanceof Authenticatable) {
                throw new AuthException(
                    'invitation_identity_proof_required',
                    'The invitation recipient identity could not be verified.',
                    403,
                );
            }
            $this->recipientProof->assertMatches($invitation, $authenticatedRecipient);
            $existingReference = SubjectReference::fromAuthenticatable($existing);
            $authenticatedReference = SubjectReference::fromAuthenticatable($authenticatedRecipient);
            if ($existingReference->type !== $authenticatedReference->type
                || $existingReference->identifier !== $authenticatedReference->identifier) {
                throw new AuthException(
                    'invitation_identity_proof_required',
                    'The invitation recipient identity could not be verified.',
                    403,
                );
            }

            return $existing;
        }

        $subject = $this->subjects->resolve($invitation, $data->toRegistrationArray());
        if (! $subject instanceof Model) {
            throw AuthException::invalidConfiguration('Invitation subjects must be persistent Eloquent principals.');
        }

        return $subject;
    }
}
