<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use Nvl\Auth\Contracts\AccountConfirmation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Support\Auth\CanonicalActorResolver;
use SensitiveParameter;

/**
 * Confirms sensitive account mutations with the subject's current password.
 *
 * @internal
 */
final readonly class PasswordAccountConfirmation implements AccountConfirmation
{
    /** Create the password-backed confirmation policy. */
    public function __construct(private Hasher $hasher, private CanonicalActorResolver $canonical) {}

    /** {@inheritDoc} */
    public function assertConfirmed(Authenticatable $subject, #[SensitiveParameter] string $credential): void
    {
        $subject = $this->canonical->resolve($subject);
        if (! $this->hasher->check($credential, (string) $subject->getAuthPassword())) {
            throw new AuthException('account_confirmation_invalid', 'Account confirmation failed.', 422);
        }
    }
}
