<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\InvitationDeliveryStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Services\FeatureGate;

/**
 * Records one bounded host delivery result against the current invitation message.
 */
final readonly class RecordInvitationDeliveryOutcomeAction
{
    /**
     * Create the delivery outcome mutation use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Record a delivered or failed outcome idempotently.
     */
    public function execute(
        string $invitationId,
        string $messageId,
        InvitationDeliveryStatus $status,
        CarbonImmutable $occurredAt,
        ?string $failureCode = null,
    ): void {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Update);
        $this->validate($invitationId, $messageId, $status, $failureCode);
        $connection = (new Invitation)->getConnectionName();

        DB::connection($connection)->transaction(function () use (
            $failureCode,
            $invitationId,
            $messageId,
            $occurredAt,
            $status,
        ): void {
            /** @var Invitation|null $invitation */
            $invitation = Invitation::query()->lockForUpdate()->find($invitationId);

            if (! $invitation instanceof Invitation) {
                throw new AuthException('invitation_unavailable', 'The invitation is unavailable.', 404);
            }

            if ($invitation->current_delivery_message_id !== $messageId) {
                $this->audits->record(
                    'invitation.delivery_outcome_stale',
                    outcome: 'ignored',
                    metadata: [
                        'invitation_id' => $invitation->identifier(),
                        'message_id' => $messageId,
                        'current_message_id' => $invitation->current_delivery_message_id,
                        'delivery_status' => $status->value,
                    ],
                );

                return;
            }

            if ($invitation->delivery_status === InvitationDeliveryStatus::Delivered
                || $invitation->delivery_status === $status) {
                return;
            }

            $attributes = [
                'delivery_status' => $status,
                'delivery_attempted_at' => $occurredAt,
                'delivered_at' => null,
                'delivery_failed_at' => null,
                'delivery_failure_code' => null,
            ];

            if ($status === InvitationDeliveryStatus::Delivered) {
                $attributes['delivered_at'] = $occurredAt;
            } else {
                $attributes['delivery_failed_at'] = $occurredAt;
                $attributes['delivery_failure_code'] = $failureCode;
            }

            $invitation->forceFill($attributes)->save();
            $this->audits->record(
                'invitation.delivery_outcome_recorded',
                outcome: $status->value,
                metadata: [
                    'invitation_id' => $invitation->identifier(),
                    'message_id' => $messageId,
                ],
            );
        }, 3);
    }

    /**
     * Validate bounded outcome input without accepting exception text.
     */
    private function validate(
        string $invitationId,
        string $messageId,
        InvitationDeliveryStatus $status,
        ?string $failureCode,
    ): void {
        foreach ([$invitationId, $messageId] as $identifier) {
            if (trim($identifier) === ''
                || $identifier !== trim($identifier)
                || mb_strlen($identifier) > 191
                || preg_match('/[\x00-\x1F\x7F]/', $identifier) === 1) {
                throw new InvalidArgumentException('Invitation outcome identifiers are invalid.');
            }
        }

        if ($status === InvitationDeliveryStatus::Pending) {
            throw new InvalidArgumentException('Invitation delivery outcomes must be Delivered or Failed.');
        }

        if ($status === InvitationDeliveryStatus::Failed
            && ($failureCode === null
                || preg_match('/\A[a-z0-9][a-z0-9_.-]{0,119}\z/', $failureCode) !== 1)) {
            throw new InvalidArgumentException('Failed invitation delivery outcomes require a safe failure code.');
        }

        if ($status === InvitationDeliveryStatus::Delivered && $failureCode !== null) {
            throw new InvalidArgumentException('A failure code is only valid for failed invitation delivery outcomes.');
        }
    }
}
