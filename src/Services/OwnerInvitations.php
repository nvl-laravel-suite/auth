<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Laravel\Sanctum\TransientToken;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\InvitationRecipientProof;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Contracts\OwnerBoundApiTokenManager;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Data\Mutations\AcceptInvitationData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Events\InvitationAccepted;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Results\InvitationRegistrationResult;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Ownership\Contracts\OwnerAvailability;
use Nvl\Ownership\Services\OwnerIdentityResolver;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Support\Events\DomainEventDispatcher;
use Nvl\Support\Ownership\Contracts\OwnershipBoundary;
use Nvl\Support\Ownership\Contracts\OwnershipReadiness;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/**
 * Consumes a bounded invitation delegation after fresh issuer and recipient checks.
 * The caller supplies no callback and never receives the issuer's execution authority.
 *
 * @internal
 */
final readonly class OwnerInvitations
{
    public function __construct(
        private Container $container,
        private SecretHasher $hasher,
        private FeatureGate $features,
        private OwnershipReadiness $readiness,
        private OwnershipBoundary $boundary,
        private InvitationRecipientProof $proof,
        private MembershipPrincipalResolver $principals,
        private OwnerMemberships $memberships,
        private AuthModelRegistry $models,
        private ManagementAuthorizer $authorization,
        private AuthPipeline $pipeline,
        private AuthCommittedAudit $audits,
        private DomainEventDispatcher $events,
        private ApiTokenManager $tokens,
        private InvitationSubjectResolver $subjects,
        private PrincipalAttributeMapper $attributes,
    ) {}

    /** Return only public invitation context to its bearer, without entering any owner. */
    public function preview(string $token): Invitation
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Read);
        [$invitation] = $this->bootstrap($token);

        return $invitation->makeHidden(['roles', 'permissions', 'metadata', 'owner_scope_key', 'owner_reference', 'tenant_id', 'ownership_key']);
    }

    /** Consume a delegation for an existing authenticated principal. */
    public function accept(string $token, Authenticatable $subject): Invitation
    {
        return $this->consume($token, $subject)->invitation;
    }

    /** Create an explicitly invited identity and its membership in the same actual transaction. */
    public function register(AcceptInvitationData $data, ?Authenticatable $subject = null): InvitationRegistrationResult
    {
        return $this->consume($data->token, $subject, $data);
    }

    /** Consume only the fixed registration/acceptance capability; no caller-supplied callback is admitted. */
    private function consume(string $token, ?Authenticatable $subject, ?AcceptInvitationData $registration = null): InvitationRegistrationResult
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Use);
        [$candidate, $reference] = $this->bootstrap($token);
        if ($registration === null) {
            if ($subject === null) {
                throw $this->invalid();
            }
            $this->proof->assertMatches($candidate, $subject);
        }
        if ($subject !== null) {
            $this->assertTokenOwner($subject, $reference);
        }
        if (! is_string($candidate->inviter_type) || ! is_string($candidate->inviter_id)) {
            throw $this->invalid();
        }
        $issuerReference = new SubjectReference($candidate->inviter_type, $candidate->inviter_id);
        $issuer = $this->principals->resolve($issuerReference);
        $owner = $this->container->make(OwnerIdentityResolver::class)->resolve($reference);

        return $this->container->make(OwnershipRunner::class)->run($owner, $issuer, function () use ($token, $subject, $issuer, $issuerReference, $registration): InvitationRegistrationResult {
            $model = new Invitation;
            $membership = new ($this->models->ownerMembershipClass());
            $principal = new ($this->models->rbacPrincipalClass());
            if ($model->getConnection() !== $membership->getConnection() || $model->getConnection() !== $principal->getConnection()) {
                throw AuthException::invalidConfiguration('Invitation, membership and principal storage must share the actual source transaction.');
            }
            $this->authorization->authorize($issuer, 'nvl.auth.invitations.create');

            return $model->getConnection()->transaction(function () use ($model, $token, $subject, $issuer, $issuerReference, $registration): InvitationRegistrationResult {
                $this->memberships->lock();
                $fresh = $this->boundary->query(Invitation::query(), 'auth.invitations')->where('token_hash', $this->hasher->hash('invitation-token', $token))->lockForUpdate()->first();
                if (! $fresh instanceof Invitation || ! $fresh->isUsable()
                    || $fresh->inviter_type !== $issuerReference->type || $fresh->inviter_id !== $issuerReference->identifier) {
                    throw $this->invalid();
                }
                if ($registration !== null) {
                    $subject = $this->resolveSubject($fresh, $registration, $subject);
                } elseif ($subject !== null) {
                    $this->proof->assertMatches($fresh, $subject);
                }
                $recipient = SubjectReference::fromAuthenticatable($subject);
                $this->principals->resolve($recipient, true);
                $this->authorization->authorize($issuer, 'nvl.auth.invitations.create', $fresh);

                return $this->pipeline->run('invitation_accepted', new AuthPipelineContext('invitation_accepted', ['invitation_id' => $fresh->identifier()], $recipient), function () use ($fresh, $recipient, $subject, $issuer, $model): InvitationRegistrationResult {
                    $membership = $this->memberships->enroll($issuer, $recipient, $fresh->roles ?? [], $fresh->permissions ?? []);
                    $fresh->forceFill(['active_key' => null, 'accepted_by_type' => $recipient->type, 'accepted_by_id' => $recipient->identifier, 'accepted_at' => now()])->save();
                    $this->audits->record($model->getConnection(), 'invitation.accepted', subject: $recipient, actor: $subject, metadata: ['invitation_id' => $fresh->identifier(), 'membership_id' => $membership->identifier()]);
                    $this->events->dispatch(new InvitationAccepted($fresh->identifier(), $fresh->type, $fresh->purpose, $recipient, $fresh->accepted_at), $model->getConnection());

                    return new InvitationRegistrationResult($fresh, $subject);
                });
            }, 3);
        });
    }

    /** Reuse an existing identity only after authenticated mailbox proof; never overwrite its credentials. */
    private function resolveSubject(Invitation $invitation, AcceptInvitationData $data, ?Authenticatable $authenticated): Authenticatable
    {
        $class = $this->models->userClass();
        $email = $this->attributes->column(PrincipalAttribute::Email);
        $existing = $class::query()->where($email, mb_strtolower(trim($invitation->recipient)))->first();
        if ($existing instanceof Authenticatable) {
            if ($authenticated === null) {
                throw new AuthException('invitation_identity_proof_required', 'The invitation recipient identity could not be verified.', 403);
            }
            $this->proof->assertMatches($invitation, $authenticated);
            if (SubjectReference::fromAuthenticatable($existing) != SubjectReference::fromAuthenticatable($authenticated)) {
                throw new AuthException('invitation_identity_proof_required', 'The invitation recipient identity could not be verified.', 403);
            }

            return $existing;
        }
        $created = $this->subjects->resolve($invitation, $data->toRegistrationArray());
        if (! $created instanceof Model || ! $created instanceof $class || ! $created->exists
            || $created->getConnection() !== $invitation->getConnection()
            || ! is_string($created->getAttribute($email))
            || mb_strtolower(trim($created->getAttribute($email))) !== mb_strtolower(trim($invitation->recipient))) {
            throw AuthException::invalidConfiguration('The invitation resolver must persist the canonical invited identity on the same source.');
        }

        return $created;
    }

    /** Look up only an exact secret before owner admission; it grants no other resource access.
     * @return array{Invitation, OwnerReference}
     */
    private function bootstrap(string $token): array
    {
        $this->readiness->assertActive('auth.invitations');
        $model = new Invitation;
        $row = $model->getConnection()->table($model->getTable())->useWritePdo()->where('token_hash', $this->hasher->hash('invitation-token', $token))->first();
        if ($row === null || ! is_string($row->owner_reference)) {
            throw $this->invalid();
        }
        $payload = json_decode($row->owner_reference, true, flags: JSON_THROW_ON_ERROR);
        if (! is_array($payload)) {
            throw $this->invalid();
        }
        $reference = OwnerReference::fromArray($payload);
        $candidate = $model->newFromBuilder(AuthStoredRow::attributes($row));
        if (! $candidate->isUsable() || $row->owner_scope_key !== $reference->scopeKey()) {
            throw $this->invalid();
        }
        $owner = $this->container->make(OwnerIdentityResolver::class)->resolve($reference);
        $this->container->make(OwnerAvailability::class)->assertAvailable($owner);

        return [$candidate, $reference];
    }

    /** Prevent an owner-bound API credential from joining another owner. */
    private function assertTokenOwner(Authenticatable $subject, OwnerReference $owner): void
    {
        if (! method_exists($subject, 'currentAccessToken')) {
            return;
        }
        $token = (new \ReflectionMethod($subject, 'currentAccessToken'))->invoke($subject);
        if ($token === null || $token instanceof TransientToken) {
            return;
        }
        $id = $token instanceof Model ? $token->getKey() : null;
        if ((! is_string($id) && ! is_int($id)) || ! $this->tokens instanceof OwnerBoundApiTokenManager
            || $this->tokens->ownerForToken($subject, (string) $id) != $owner) {
            throw new AuthException('owner_token_invalid', 'The credential cannot accept an invitation for this owner.', 403);
        }
    }

    private function invalid(): AuthException
    {
        return new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
    }
}
