<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Data\Mutations\AcceptInvitationData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\InvitationAccepted;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Results\InvitationRegistrationResult;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\RbacManager;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;

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
        private RbacManager $rbac,
        private AuthPipeline $pipeline,
        private AuthAuditRecorder $audits,
        private AuthModelRegistry $models,
    ) {}

    /** Register the invited subject and return the consumed invitation and subject. */
    public function execute(AcceptInvitationData $data): InvitationRegistrationResult
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Use);
        $connection = (new Invitation)->getConnectionName();
        $principalClass = $this->models->userClass();
        $principalConnection = (new $principalClass)->getConnectionName();

        if ($principalConnection !== $connection) {
            throw AuthException::invalidConfiguration(
                'Invitation registration requires principal and invitation storage on one connection.',
            );
        }

        try {
            return DB::connection($connection)->transaction(function () use ($data): InvitationRegistrationResult {
                /** @var Invitation|null $invitation */
                $invitation = Invitation::query()
                    ->where('token_hash', $this->hasher->hash('invitation-token', $data->token))
                    ->lockForUpdate()
                    ->first();

                if (! $invitation instanceof Invitation || ! $invitation->isUsable()) {
                    throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
                }

                $subject = $this->subjects->resolve($invitation, $data->toRegistrationArray());
                $reference = SubjectReference::fromAuthenticatable($subject);

                return $this->pipeline->run(
                    'invitation_accepted',
                    new AuthPipelineContext('invitation_accepted', [
                        'invitation_id' => $invitation->identifier(),
                        'type' => $invitation->type,
                        'purpose' => $invitation->purpose,
                        'metadata' => $invitation->metadata,
                    ], $reference),
                    function () use ($invitation, $reference, $subject): InvitationRegistrationResult {
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
                        PrincipalChanged::dispatch($reference->identifier, 'invitation_registered');

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
}
