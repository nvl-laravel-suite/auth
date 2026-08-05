<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Clients;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthClientSession;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Ends one correlation record without attempting to own the Laravel session.
 */
final readonly class EndAuthClientSessionAction
{
    /**
     * Create the session-end use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * End one client-session record idempotently.
     */
    public function execute(AuthClientSession $session, string $reason = 'logout'): AuthClientSession
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Revoke);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Revoke);
        $reason = trim($reason);

        if ($reason === '' || mb_strlen($reason) > 64 || preg_match('/[\x00-\x1F\x7F]/', $reason) === 1) {
            throw new AuthException('client_session_reason_invalid', 'The client session end reason is invalid.', 422);
        }

        return DB::connection($session->getConnectionName())->transaction(function () use ($reason, $session): AuthClientSession {
            /** @var AuthClientSession $locked */
            $locked = AuthClientSession::query()->whereKey($session->identifier())->lockForUpdate()->firstOrFail();

            if ($locked->ended_at === null) {
                $locked->forceFill([
                    'ended_at' => CarbonImmutable::now(),
                    'end_reason' => $reason,
                ])->save();
                $subject = $locked->subject_type !== null && $locked->subject_id !== null
                    ? new SubjectReference($locked->subject_type, $locked->subject_id)
                    : null;
                $this->audits->record(
                    'client.session_ended',
                    subject: $subject,
                    clientId: $locked->client_id,
                    metadata: ['client_session_id' => $locked->identifier(), 'reason' => $reason],
                );
            }

            return $locked;
        }, 3);
    }
}
