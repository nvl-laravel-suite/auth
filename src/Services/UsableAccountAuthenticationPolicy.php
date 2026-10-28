<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AccountAuthenticationPolicy;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Mandatory native ownership and last-primary protection, also the default consumer policy.
 *
 * @api
 */
final readonly class UsableAccountAuthenticationPolicy implements AccountAuthenticationPolicy
{
    public function __construct(private AuthAccountSecurity $inventory, private PrincipalSecurity $security) {}

    public function assertRemovalAllowed(Authenticatable $subject, string $kind, string $credentialId): void
    {
        if (! in_array($kind, ['password', 'passkey', 'social', 'totp', 'recovery'], true)) {
            throw new \InvalidArgumentException('Unknown credential kind.');
        }
        $this->security->lock($subject);
        $state = $this->inventory->state($subject);
        if (in_array($kind, ['totp', 'recovery'], true)) {
            return;
        }
        $passkeys = array_column($state['passkeys'], 'id');
        $social = array_column($state['socialIdentities'], 'id');
        $usable = match ($kind) {
            'password' => $credentialId === 'password' && $state['hasPassword'], 'passkey' => in_array($credentialId, $passkeys, true), default => in_array($credentialId, $social, true)
        };
        if ($kind === 'password') {
            $owned = $credentialId === 'password' && filled($subject->getAuthPassword());
        } else {
            $model = $kind === 'passkey' ? new Passkey : new SocialIdentity;
            $reference = SubjectReference::fromAuthenticatable($subject);
            $owned = $model->newQuery()->whereKey($credentialId)->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNull('revoked_at')->exists();
        }
        if (! $owned) {
            throw new AuthException('credential_unavailable', 'The credential is unavailable.', 422);
        }
        $remaining = ($state['hasPassword'] ? 1 : 0) + count($passkeys) + count($social) + ($this->inventory->hasEmailMethod($subject) ? 1 : 0) - ($usable ? 1 : 0);
        if ($remaining < 1) {
            throw new AuthException('last_authentication_method', 'Keep at least one usable primary authentication method.', 422);
        }
    }
}
