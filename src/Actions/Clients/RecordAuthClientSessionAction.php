<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Clients;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use JsonException;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthClient;
use Nvl\Auth\Models\AuthClientSession;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Correlates an existing Laravel session with one first-party Auth client.
 */
final readonly class RecordAuthClientSessionAction
{
    /**
     * Create the session-correlation use case.
     */
    public function __construct(
        private FeatureGate $features,
        private SecretHasher $hasher,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Create or refresh one client-session correlation record.
     *
     * @param  array<string, mixed>  $metadata
     */
    public function execute(
        AuthClient $client,
        string $sessionId,
        ?Authenticatable $subject = null,
        ?string $ipAddress = null,
        ?string $userAgent = null,
        array $metadata = [],
    ): AuthClientSession {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Issue);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);

        if (trim($sessionId) === ''
            || mb_strlen($sessionId) > 255
            || preg_match('/[\x00-\x1F\x7F]/', $sessionId) === 1
            || ($ipAddress !== null && mb_strlen($ipAddress) > 64)
            || ($userAgent !== null && mb_strlen($userAgent) > 1_024)) {
            throw new AuthException('client_session_input_invalid', 'The client session input is invalid.', 422);
        }

        try {
            $encodedMetadata = json_encode($metadata, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new AuthException(
                'client_session_input_invalid',
                'The client session metadata is invalid.',
                422,
                previous: $exception,
            );
        }

        if (strlen($encodedMetadata) > 32_768) {
            throw new AuthException('client_session_input_invalid', 'The client session metadata is too large.', 422);
        }

        $reference = $subject instanceof Authenticatable
            ? SubjectReference::fromAuthenticatable($subject)
            : null;
        $hash = $this->hasher->hash('client-session', $sessionId);

        try {
            return DB::connection($client->getConnectionName())->transaction(function () use (
                $client,
                $hash,
                $ipAddress,
                $metadata,
                $reference,
                $subject,
                $userAgent,
            ): AuthClientSession {
                /** @var AuthClient|null $lockedClient */
                $lockedClient = AuthClient::query()->whereKey($client->identifier())->lockForUpdate()->first();

                if (! $lockedClient instanceof AuthClient || ! $lockedClient->is_active) {
                    throw new AuthException('client_unavailable', 'The authentication client is unavailable.', 404);
                }

                /** @var AuthClientSession|null $session */
                $session = AuthClientSession::query()
                    ->where('client_id', $lockedClient->identifier())
                    ->where('session_id_hash', $hash)
                    ->lockForUpdate()
                    ->first();

                if ($session instanceof AuthClientSession && $session->ended_at !== null) {
                    throw new AuthException('client_session_ended', 'The client session has ended.', 409);
                }

                $session ??= new AuthClientSession([
                    'client_id' => $lockedClient->identifier(),
                    'session_id_hash' => $hash,
                ]);
                $session->fill([
                    'subject_type' => $reference?->type,
                    'subject_id' => $reference?->identifier,
                    'ip_address' => $ipAddress,
                    'user_agent' => $userAgent,
                    'metadata' => $metadata,
                    'authenticated_at' => $reference === null ? null : CarbonImmutable::now(),
                    'last_seen_at' => CarbonImmutable::now(),
                ])->save();
                $this->audits->record(
                    'client.session_recorded',
                    subject: $reference,
                    actor: $subject,
                    clientId: $lockedClient->identifier(),
                    metadata: ['client_session_id' => $session->identifier()],
                );

                return $session;
            }, 3);
        } catch (QueryException $exception) {
            if (in_array($exception->errorInfo[0] ?? null, ['23000', '23505'], true)
                && (str_contains($exception->getMessage(), 'nvl_auth_client_sessions_client_hash_unique')
                    || str_contains($exception->getMessage(), 'auth_client_sessions.client_id'))) {
                throw new AuthException(
                    'client_session_conflict',
                    'The client session is already being recorded.',
                    409,
                    previous: $exception,
                );
            }

            throw $exception;
        }
    }
}
