<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Exceptions\AuthException;

/**
 * Updates conventional Eloquent authenticatable passwords through Laravel hashing.
 */
final readonly class EloquentPasswordUpdater implements PasswordUpdater
{
    /**
     * Create the conventional Eloquent updater.
     */
    public function __construct(private Hasher $hasher) {}

    /**
     * Persist a replacement password and rotate the remember token.
     */
    public function update(CanResetPassword $subject, string $password): void
    {
        if (! $subject instanceof Model) {
            throw AuthException::invalidConfiguration(
                'The default password updater requires an Eloquent resettable model.',
            );
        }

        $passwordName = method_exists($subject, 'getAuthPasswordName')
            ? $subject->getAuthPasswordName()
            : 'password';
        $subject->forceFill([
            $passwordName => $this->hasher->make($password),
        ]);

        if (method_exists($subject, 'setRememberToken')) {
            $subject->setRememberToken(Str::random(60));
        }

        $subject->save();
    }
}
