<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Auth\CanonicalActorResolver;

/**
 * Safe account method inventory; stored credential material never leaves this reader.
 *
 * @api
 */
final readonly class AuthAccountSecurity
{
    public function __construct(private CanonicalActorResolver $canonical, private AuthConfiguration $configuration, private SocialProviderRegistry $providers) {}

    /** @return array{hasPassword: bool, passkeys: list<array{id: string, name: ?string, lastUsedAt: ?CarbonImmutable}>, socialIdentities: list<array{id: string, provider: string}>, totpEnabled: bool, recoveryCodesRemaining: int} */
    public function state(Authenticatable $subject): array
    {
        $subject = $this->canonical->resolve($subject);
        $passkeys = [];
        if ($this->configuration->featureEnabled(AuthFeature::Passkeys)) {
            foreach ($this->forSubject(Passkey::query(), $subject)->whereNull('revoked_at')->get() as $passkey) {
                $passkeys[] = ['id' => $passkey->identifier(), 'name' => $passkey->name, 'lastUsedAt' => $passkey->last_used_at];
            }
        }
        $identities = [];
        if ($this->configuration->featureEnabled(AuthFeature::SocialIdentities)) {
            $providers = $this->providers->providers();
            foreach ($this->forSubject(SocialIdentity::query(), $subject)->whereNull('revoked_at')->get() as $identity) {
                if ($providers[$identity->provider]['enabled'] ?? false) {
                    $identities[] = ['id' => $identity->identifier(), 'provider' => $identity->provider];
                }
            }
        }
        $totp = new TotpCredential;
        $codes = new RecoveryCode;
        $totpEnabled = $totp->getConnection()->getSchemaBuilder()->hasTable($totp->getTable()) && $this->forSubject(TotpCredential::query(), $subject)->whereNotNull('confirmed_at')->whereNull('revoked_at')->exists();
        $remaining = $codes->getConnection()->getSchemaBuilder()->hasTable($codes->getTable()) ? $this->forSubject(RecoveryCode::query(), $subject)->whereNull('revoked_at')->whereNull('used_at')->count() : 0;

        return ['hasPassword' => $this->configuration->featureEnabled(AuthFeature::Password) && filled($subject->getAuthPassword()), 'passkeys' => $passkeys, 'socialIdentities' => $identities, 'totpEnabled' => $totpEnabled, 'recoveryCodesRemaining' => $remaining];
    }

    /**
     * Native verified email methods count only when an actual login feature is selected.
     *
     * @internal
     */
    public function hasEmailMethod(Authenticatable $subject): bool
    {
        $subject = $this->canonical->resolve($subject);

        return $subject instanceof MustVerifyEmail && $subject->hasVerifiedEmail() && ($this->configuration->featureEnabled(AuthFeature::MagicLinks) || $this->configuration->featureEnabled(AuthFeature::SecurityCodes));
    }

    /** @template TModel of Passkey|SocialIdentity|TotpCredential|RecoveryCode
     * @param  Builder<TModel>  $query
     * @return Builder<TModel>
     */
    private function forSubject(Builder $query, Authenticatable $subject): Builder
    {
        $model = $query->getModel();
        if (! $subject instanceof Model || $model->getConnection() !== $subject->getConnection()) {
            throw AuthException::invalidConfiguration('Account security inventory requires one canonical source.');
        }
        $reference = SubjectReference::fromAuthenticatable($subject);

        return $query->where('subject_type', $reference->type)->where('subject_id', $reference->identifier);
    }
}
