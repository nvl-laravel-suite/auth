<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\InvitationRegistrationMapper;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Models\Invitation;

/**
 * Resolves existing package users or provisions an invited package principal.
 *
 * The caller owns the transaction so provisioning and invitation consumption
 * remain one atomic operation.
 *
 * @internal
 */
final readonly class PackageInvitationSubjectResolver implements InvitationSubjectResolver
{
    /** Create the package invitation subject resolver. */
    public function __construct(
        private AuthModelRegistry $models,
        private InvitationRegistrationMapper $registration,
        private PrincipalAttributeMapper $attributes,
        private PasswordUpdater $passwords,
    ) {}

    /** {@inheritDoc} */
    public function resolve(Invitation $invitation, #[\SensitiveParameter] array $input): Authenticatable
    {
        $class = $this->models->userClass();
        $mapped = $this->registration->map($invitation, $input);
        unset($mapped[$this->attributes->column(PrincipalAttribute::Password)]);
        $user = $class::query()->create($mapped);
        if (is_string($input['password'] ?? null)) {
            $this->passwords->update($user, $input['password']);
            $user->setRememberToken(Str::random(60));
            $user->save();
        }

        return $user;
    }
}
