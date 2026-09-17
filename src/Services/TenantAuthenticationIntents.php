<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use Nvl\Auth\Enums\TenantAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\TenantAuthenticationIntent;
use Nvl\Auth\ValueObjects\IssuedTenantAuthenticationIntent;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantDirectory;
use Nvl\Tenancy\Enums\TenantStatus;
use Nvl\Tenancy\ValueObjects\TenantId;

/** Issues and atomically consumes short-lived tenant-selection authentication intents. */
final readonly class TenantAuthenticationIntents
{
    public function __construct(
        private AuthConfiguration $configuration,
        private OpaqueTokenFactory $tokens,
        private SecretHasher $hasher,
        private TenantDirectory $directory,
    ) {}

    public function issue(
        TenantId $tenant,
        TenantAuthenticationPurpose $purpose,
        string $sessionBinding,
        ?SubjectReference $subject = null,
        ?string $provider = null,
        ?string $returnPath = null,
    ): IssuedTenantAuthenticationIntent {
        $this->validateBinding($sessionBinding);
        $this->validateProvider($provider);
        $this->validateReturnPath($returnPath);
        $this->assertActiveTenant($tenant);
        $nonce = $this->tokens->make();
        $expiresAt = CarbonImmutable::instance(now())->addMinutes($this->configuration->integerBetween(
            'features.authentication.settings.tenant_intent_ttl_minutes',
            10,
            1,
            60,
        ));
        $intent = TenantAuthenticationIntent::query()->create([
            'tenant_id' => $tenant->value,
            'purpose' => $purpose,
            'nonce_hash' => $this->hasher->hash('tenant-authentication-intent', $nonce),
            'session_binding_hash' => $this->hasher->hash('tenant-authentication-session', $sessionBinding),
            'subject_type' => $subject?->type,
            'subject_id' => $subject?->identifier,
            'payload' => ['provider' => $provider, 'return_path' => $returnPath],
            'expires_at' => $expiresAt,
        ]);

        return new IssuedTenantAuthenticationIntent($intent->identifier(), $nonce, $expiresAt);
    }

    public function consume(
        string $nonce,
        TenantAuthenticationPurpose $purpose,
        string $sessionBinding,
        TenantId $expectedTenant,
        ?SubjectReference $subject = null,
        ?string $provider = null,
    ): TenantId {
        $this->validateBinding($sessionBinding);
        $this->validateProvider($provider);
        $nonceHash = $this->hasher->hash('tenant-authentication-intent', $nonce);
        $connection = (new TenantAuthenticationIntent)->getConnectionName();

        return DB::connection($connection)->transaction(function () use (
            $nonceHash,
            $provider,
            $purpose,
            $sessionBinding,
            $subject,
            $expectedTenant,
        ): TenantId {
            /** @var TenantAuthenticationIntent|null $intent */
            $intent = TenantAuthenticationIntent::query()
                ->where('nonce_hash', $nonceHash)
                ->where('expires_at', '>', now())
                ->lockForUpdate()
                ->first();
            $payload = $intent?->payload;
            $providerMatches = is_array($payload) && ($payload['provider'] ?? null) === $provider;
            $subjectMatches = $intent instanceof TenantAuthenticationIntent
                && $intent->subject_type === $subject?->type
                && $intent->subject_id === $subject?->identifier;
            if (! $intent instanceof TenantAuthenticationIntent
                || ! hash_equals($intent->nonce_hash, $nonceHash)
                || ! hash_equals(
                    $intent->session_binding_hash,
                    $this->hasher->hash('tenant-authentication-session', $sessionBinding),
                )
                || $intent->purpose !== $purpose
                || $intent->tenant_id !== $expectedTenant->value
                || ! $providerMatches
                || ! $subjectMatches
                || $intent->consumed_at !== null) {
                throw new AuthException('tenant_authentication_intent_invalid', 'The tenant authentication intent is invalid.', 410);
            }

            $this->assertActiveTenant($expectedTenant);
            $intent->forceFill([
                'consumed_at' => CarbonImmutable::instance(now()),
            ])->save();

            return $expectedTenant;
        }, 3);
    }

    private function assertActiveTenant(TenantId $tenant): void
    {
        $descriptor = $this->directory->find($tenant);
        if ($descriptor->id->value !== $tenant->value || $descriptor->status !== TenantStatus::Active) {
            throw new AuthException('tenant_authentication_intent_invalid', 'The tenant authentication intent is invalid.', 410);
        }
    }

    private function validateBinding(string $binding): void
    {
        if (trim($binding) === '' || $binding !== trim($binding) || mb_strlen($binding) > 512) {
            throw new InvalidArgumentException('Tenant authentication session bindings are invalid.');
        }
    }

    private function validateProvider(?string $provider): void
    {
        if ($provider !== null && preg_match('/\A[a-z0-9][a-z0-9_.-]{0,79}\z/', $provider) !== 1) {
            throw new InvalidArgumentException('Tenant authentication providers are invalid.');
        }
    }

    private function validateReturnPath(?string $returnPath): void
    {
        if ($returnPath !== null && (! str_starts_with($returnPath, '/')
            || str_starts_with($returnPath, '//')
            || mb_strlen($returnPath) > 1_024
            || parse_url($returnPath, PHP_URL_HOST) !== null
            || preg_match('/[\x00-\x1F\x7F]/', $returnPath) === 1)) {
            throw new InvalidArgumentException('Tenant authentication return paths must be local paths.');
        }
    }
}
