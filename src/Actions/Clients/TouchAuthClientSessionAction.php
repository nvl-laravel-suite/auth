<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Clients;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthClientSession;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\SecretHasher;

/**
 * Refreshes activity for an existing client-session correlation.
 */
final readonly class TouchAuthClientSessionAction
{
    /**
     * Create the session touch use case.
     */
    public function __construct(
        private FeatureGate $features,
        private SecretHasher $hasher,
    ) {}

    /**
     * Touch one active correlation by its host session identifier.
     */
    public function execute(string $clientId, string $sessionId): AuthClientSession
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Update);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);

        if (trim($sessionId) === ''
            || mb_strlen($sessionId) > 255
            || preg_match('/[\x00-\x1F\x7F]/', $sessionId) === 1) {
            throw new AuthException('client_session_input_invalid', 'The client session input is invalid.', 422);
        }

        $connection = (new AuthClientSession)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($clientId, $sessionId): AuthClientSession {
            /** @var AuthClientSession|null $session */
            $session = AuthClientSession::query()
                ->where('client_id', $clientId)
                ->where('session_id_hash', $this->hasher->hash('client-session', $sessionId))
                ->whereNull('ended_at')
                ->lockForUpdate()
                ->first();

            if (! $session instanceof AuthClientSession) {
                throw new AuthException('client_session_unavailable', 'The client session is unavailable.', 404);
            }

            $session->forceFill(['last_seen_at' => CarbonImmutable::now()])->save();

            return $session;
        }, 3);
    }
}
