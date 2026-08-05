<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\User;

/**
 * Resolves existing package users or provisions an invited package principal.
 *
 * The resolver owns a small transaction because the resolver contract is the
 * stable reusable provisioning boundary used by public invitation acceptance.
 */
final readonly class PackageInvitationSubjectResolver implements InvitationSubjectResolver
{
    /** Create the package invitation subject resolver. */
    public function __construct(
        private AuthModelRegistry $models,
        private AuthConfiguration $configuration,
    ) {}

    /** {@inheritDoc} */
    public function resolve(Invitation $invitation, array $input): Authenticatable
    {
        $email = mb_strtolower(trim($invitation->recipient));
        $class = $this->models->userClass();
        $existing = $class::query()->where('email', $email)->first();

        if ($existing instanceof User) {
            return $existing;
        }

        $name = $input['name'] ?? null;
        $password = $input['password'] ?? null;

        if (! is_string($name) || trim($name) === '' || mb_strlen($name) > 160
            || ! is_string($password) || mb_strlen($password) < 12) {
            throw new AuthException(
                'invitation_registration_invalid',
                'Invitation registration requires a valid name and a password of at least 12 characters.',
                422,
            );
        }

        $connection = (new $class)->getConnectionName();

        try {
            return DB::connection($connection)->transaction(function () use ($class, $email, $input, $name, $password): User {
                return $class::query()->create([
                    'name' => trim($name),
                    'email' => $email,
                    'password' => $password,
                    'is_active' => true,
                    'locale' => $this->boundedString($input['locale'] ?? null, 12)
                        ?? $this->configuration->string('features.principal_management.settings.default_locale', 'en'),
                    'timezone' => $this->boundedString($input['timezone'] ?? null, 64)
                        ?? $this->configuration->string('features.principal_management.settings.default_timezone', 'UTC'),
                    'profile' => is_array($input['profile'] ?? null) ? $input['profile'] : [],
                ]);
            }, 3);
        } catch (QueryException $exception) {
            $concurrent = $class::query()->where('email', $email)->first();

            if ($concurrent instanceof User) {
                return $concurrent;
            }

            throw $exception;
        }
    }

    /** Return one bounded optional string. */
    private function boundedString(mixed $value, int $maximum): ?string
    {
        return is_string($value) && trim($value) !== '' && mb_strlen($value) <= $maximum
            ? trim($value)
            : null;
    }
}
