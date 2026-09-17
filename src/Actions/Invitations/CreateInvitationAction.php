<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\InvitationDeliveryStatus;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Results\IssuedInvitation;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\InvitationDeliveryMetadataPolicy;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\OpaqueTokenFactory;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\Services\TenantMembershipAssignments;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\InvitationIssuanceContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Tenancy\Services\TenantBoundary;
use Nvl\Tenancy\ValueObjects\TenantId;

/**
 * Issues one simple invitation and publishes its delivery payload after commit.
 */
final readonly class CreateInvitationAction
{
    /**
     * Create the invitation issuance use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private OpaqueTokenFactory $tokens,
        private SecretHasher $hasher,
        private ManagementAuthorizer $authorization,
        private AuthPipeline $pipeline,
        private AuthAuditRecorder $audits,
        private TenantBoundary $boundary,
        private TenantMembershipAccess $membershipAccess,
        private TenantMembershipAssignments $assignments,
        private ?InvitationDeliveryMetadataPolicy $deliveryMetadata = null,
    ) {}

    /**
     * Issue one invitation.
     */
    public function execute(
        StoreInvitationData $data,
        ?Authenticatable $actor = null,
        ?InvitationIssuanceContext $context = null,
    ): IssuedInvitation {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Issue);
        $context ??= new InvitationIssuanceContext;

        if ($actor instanceof Authenticatable) {
            $this->authorization->authorize($actor, 'nvl-auth.invitations.create');
        } elseif (! $context->actorlessAuthorized) {
            throw new AuthException('forbidden', 'Actorless invitation issuance was not explicitly authorized.', 403);
        }

        $ownership = $this->boundary->attributes('auth.invitations');
        $tenant = isset($ownership['tenant_id']) && is_string($ownership['tenant_id'])
            ? new TenantId($ownership['tenant_id'])
            : null;
        if ($context->tenant !== null && $context->tenant->value !== $tenant?->value) {
            throw new AuthException('invitation_invalid', 'The invitation request is invalid.', 410);
        }
        if ($tenant !== null) {
            if (! $actor instanceof Authenticatable) {
                throw new AuthException('forbidden', 'Tenant invitation issuance requires an authenticated member.', 403);
            }
            $this->membershipAccess->assertMember($actor, $tenant);
        } elseif (config('tenancy.enabled') === true && ($data->roles !== [] || $data->permissions !== [])) {
            throw new AuthException('invitation_assignment_invalid', 'Platform invitations cannot carry tenant access assignments.', 422);
        }

        if ($data->roles !== [] || $data->permissions !== []) {
            $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        }

        $recipient = mb_strtolower(trim($data->recipient));
        $recipientHash = $this->hasher->hash('invitation-recipient', $recipient);
        $ownershipKey = is_string($ownership['ownership_key'] ?? null) ? $ownership['ownership_key'] : 'platform';
        $activeKey = $this->hasher->hash('active-invitation', $ownershipKey."\0".$recipientHash."\0".$data->purpose);
        $grants = $tenant === null
            ? ['roles' => $data->roles, 'permissions' => $data->permissions]
            : $this->assignments->canonicalIdentifiers($data->roles, $data->permissions);
        $actorReference = $actor instanceof Authenticatable
            ? SubjectReference::fromAuthenticatable($actor)
            : null;

        return $this->pipeline->run(
            'invitation_issued',
            new AuthPipelineContext('invitation_issued', [
                'recipient_hash' => $recipientHash,
                'purpose' => $data->purpose,
                'context' => $data->context,
            ], $actorReference),
            function () use ($activeKey, $actor, $actorReference, $context, $data, $grants, $ownership, $recipient, $recipientHash, $tenant): IssuedInvitation {
                $connection = (new Invitation)->getConnectionName();

                try {
                    return DB::connection($connection)->transaction(function () use (
                        $actor,
                        $activeKey,
                        $actorReference,
                        $data,
                        $context,
                        $connection,
                        $recipient,
                        $recipientHash,
                        $grants,
                        $ownership,
                        $tenant,
                    ): IssuedInvitation {
                        $this->boundary->query(Invitation::query(), 'auth.invitations')
                            ->where('active_key', $activeKey)
                            ->where('expires_at', '<=', CarbonImmutable::now())
                            ->update(['active_key' => null]);
                        $duplicate = $this->boundary->query(Invitation::query(), 'auth.invitations')
                            ->where('active_key', $activeKey)
                            ->exists();

                        if ($duplicate) {
                            throw $this->duplicateInvitation();
                        }

                        $token = $this->tokens->make();
                        $messageId = (string) Str::uuid();
                        $expiresAt = $context->expiresAt ?? CarbonImmutable::now()->addHours(
                            $this->configuration->integerBetween(
                                'features.invitations.settings.ttl_hours',
                                72,
                                1,
                                8_760,
                            ),
                        );
                        $invitation = Invitation::query()->create([
                            ...$ownership,
                            'token_hash' => $this->hasher->hash('invitation-token', $token),
                            'active_key' => $activeKey,
                            'recipient' => $recipient,
                            'recipient_hash' => $recipientHash,
                            'context_hash' => $data->context === null
                                ? null
                                : $this->hasher->hash('invitation-context', trim($data->context)),
                            'type' => $data->type,
                            'purpose' => $data->purpose,
                            'inviter_type' => $actorReference?->type,
                            'inviter_id' => $actorReference?->identifier,
                            'roles' => $grants['roles'],
                            'permissions' => $grants['permissions'],
                            'metadata' => [
                                ...$data->metadata,
                                'return_path' => $context->returnPath,
                            ],
                            'resend_count' => 0,
                            'current_delivery_message_id' => $messageId,
                            'delivery_status' => InvitationDeliveryStatus::Pending,
                            'last_sent_at' => CarbonImmutable::now(),
                            'expires_at' => $expiresAt,
                        ]);

                        $delivery = new AuthDeliveryRequest(
                            messageId: $messageId,
                            feature: AuthFeature::Invitations,
                            type: AuthMessageType::Invitation,
                            recipient: $recipient,
                            payload: [
                                'invitation_id' => $invitation->identifier(),
                                'token' => $token,
                                'type' => $data->type,
                                'purpose' => $data->purpose,
                                'return_path' => $context->returnPath,
                            ],
                            expiresAt: $expiresAt,
                            locale: $data->locale,
                            metadata: [
                                'invitation_id' => $invitation->identifier(),
                                'context' => $data->context,
                            ],
                            invitation: ($this->deliveryMetadata ?? new InvitationDeliveryMetadataPolicy(
                                $this->configuration,
                            ))->deliveryData($invitation),
                            tenant: $tenant,
                        );
                        DB::connection($connection)->afterCommit(function () use ($actor, $data, $delivery, $invitation): void {
                            $this->audits->record(
                                'invitation.issued',
                                actor: $actor,
                                metadata: ['invitation_id' => $invitation->identifier(), 'purpose' => $data->purpose],
                            );
                            AuthDeliveryRequested::dispatch($delivery);
                        });

                        return new IssuedInvitation($invitation, $token);
                    }, 3);
                } catch (QueryException $exception) {
                    if (in_array($exception->errorInfo[0] ?? null, ['23000', '23505'], true)
                        && (str_contains($exception->getMessage(), 'nvl_auth_invitations_active_key_unique')
                            || str_contains($exception->getMessage(), 'auth_invitations.active_key'))) {
                        throw $this->duplicateInvitation($exception);
                    }

                    throw $exception;
                }
            },
        );
    }

    /**
     * Build the stable active-invitation conflict.
     */
    private function duplicateInvitation(?QueryException $previous = null): AuthException
    {
        return new AuthException(
            'invitation_exists',
            'An active invitation already exists for this recipient and purpose.',
            409,
            previous: $previous,
        );
    }
}
