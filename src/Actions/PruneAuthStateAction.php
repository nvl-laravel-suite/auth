<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\AuthClientSession;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;

/**
 * Prunes terminal, retention-expired Auth state without deleting audits.
 */
final readonly class PruneAuthStateAction
{
    /**
     * Create the terminal-state pruning use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Count or delete terminal records older than retention.
     *
     * @return array<string, int>
     */
    public function execute(bool $dryRun = false): array
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Cleanup);
        $this->features->assertAllowed(AuthFeature::MagicLinks, FeatureOperation::Cleanup);
        $this->features->assertAllowed(AuthFeature::SecurityCodes, FeatureOperation::Cleanup);
        $this->features->assertAllowed(AuthFeature::Totp, FeatureOperation::Cleanup);
        $this->features->assertAllowed(AuthFeature::Passkeys, FeatureOperation::Cleanup);
        $this->features->assertAllowed(AuthFeature::RecoveryCodes, FeatureOperation::Cleanup);
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Cleanup);
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Cleanup);
        $cutoff = CarbonImmutable::now()->subDays(
            $this->configuration->integerBetween('cleanup.retention_days', 30, 1, 3_650),
        );
        $queries = [
            'invitations' => Invitation::query()->where(function (Builder $query) use ($cutoff): void {
                $query->where('expires_at', '<', $cutoff)
                    ->orWhere('accepted_at', '<', $cutoff)
                    ->orWhere('revoked_at', '<', $cutoff);
            }),
            'challenges' => Challenge::query()->where(function (Builder $query) use ($cutoff): void {
                $query->where('expires_at', '<', $cutoff)
                    ->orWhere('consumed_at', '<', $cutoff)
                    ->orWhere('revoked_at', '<', $cutoff);
            }),
            'totp_credentials' => TotpCredential::query()->where('revoked_at', '<', $cutoff),
            'passkeys' => Passkey::query()->where('revoked_at', '<', $cutoff),
            'recovery_codes' => RecoveryCode::query()->where(function (Builder $query) use ($cutoff): void {
                $query->where('used_at', '<', $cutoff)->orWhere('revoked_at', '<', $cutoff);
            }),
            'social_identities' => SocialIdentity::query()->where('revoked_at', '<', $cutoff),
            'client_sessions' => AuthClientSession::query()->where('ended_at', '<', $cutoff),
        ];
        $connection = (new Invitation)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($dryRun, $queries): array {
            $counts = [];

            foreach ($queries as $name => $query) {
                $result = $dryRun ? $query->count() : $query->delete();

                if (! is_int($result)) {
                    throw new \LogicException('Auth pruning returned a non-integer result.');
                }

                $counts[$name] = $result;
            }

            if (! $dryRun) {
                $this->audits->record('auth_state.pruned', metadata: ['counts' => $counts]);
            }

            return $counts;
        }, 3);
    }
}
