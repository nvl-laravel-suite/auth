<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Results\IssuedInvitation;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\OpaqueTokenFactory;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;

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
    ) {}

    /**
     * Issue one invitation.
     */
    public function execute(
        StoreInvitationData $data,
        Authenticatable $actor,
    ): IssuedInvitation {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Issue);
        $this->authorization->authorize($actor, 'nvl-auth.invitations.create');

        if ($data->roles !== [] || $data->permissions !== []) {
            $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        }

        $recipient = mb_strtolower(trim($data->recipient));
        $recipientHash = $this->hasher->hash('invitation-recipient', $recipient);
        $activeKey = $this->hasher->hash('active-invitation', $recipientHash."\0".$data->purpose);
        $actorReference = SubjectReference::fromAuthenticatable($actor);

        return $this->pipeline->run(
            'invitation_issued',
            new AuthPipelineContext('invitation_issued', [
                'recipient_hash' => $recipientHash,
                'purpose' => $data->purpose,
            ], $actorReference),
            function () use ($activeKey, $actor, $actorReference, $data, $recipient, $recipientHash): IssuedInvitation {
                $connection = (new Invitation)->getConnectionName();

                try {
                    return DB::connection($connection)->transaction(function () use (
                        $actor,
                        $activeKey,
                        $actorReference,
                        $data,
                        $recipient,
                        $recipientHash,
                    ): IssuedInvitation {
                        Invitation::query()
                            ->where('active_key', $activeKey)
                            ->where('expires_at', '<=', CarbonImmutable::now())
                            ->update(['active_key' => null]);
                        $duplicate = Invitation::query()
                            ->where('active_key', $activeKey)
                            ->exists();

                        if ($duplicate) {
                            throw $this->duplicateInvitation();
                        }

                        $token = $this->tokens->make();
                        $expiresAt = CarbonImmutable::now()->addHours(
                            $this->configuration->integerBetween(
                                'features.invitations.settings.ttl_hours',
                                72,
                                1,
                                8_760,
                            ),
                        );
                        $invitation = Invitation::query()->create([
                            'token_hash' => $this->hasher->hash('invitation-token', $token),
                            'active_key' => $activeKey,
                            'recipient' => $recipient,
                            'recipient_hash' => $recipientHash,
                            'type' => $data->type,
                            'purpose' => $data->purpose,
                            'inviter_type' => $actorReference->type,
                            'inviter_id' => $actorReference->identifier,
                            'roles' => $data->roles,
                            'permissions' => $data->permissions,
                            'metadata' => $data->metadata,
                            'last_sent_at' => CarbonImmutable::now(),
                            'expires_at' => $expiresAt,
                        ]);

                        AuthDeliveryRequested::dispatch(new AuthDeliveryRequest(
                            messageId: (string) Str::uuid(),
                            feature: AuthFeature::Invitations,
                            type: AuthMessageType::Invitation,
                            recipient: $recipient,
                            payload: [
                                'invitation_id' => $invitation->identifier(),
                                'token' => $token,
                                'type' => $data->type,
                                'purpose' => $data->purpose,
                            ],
                            expiresAt: $expiresAt,
                            locale: $data->locale,
                            metadata: ['invitation_id' => $invitation->identifier()],
                        ));
                        $this->audits->record(
                            'invitation.issued',
                            actor: $actor,
                            metadata: ['invitation_id' => $invitation->identifier(), 'purpose' => $data->purpose],
                        );

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
