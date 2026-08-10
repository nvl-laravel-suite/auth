<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\InvitationRegistrationMapper;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\User;

/**
 * Resolves existing package users or provisions an invited package principal.
 *
 * The caller owns the transaction so provisioning and invitation consumption
 * remain one atomic operation.
 */
final readonly class PackageInvitationSubjectResolver implements InvitationSubjectResolver
{
    /** Create the package invitation subject resolver. */
    public function __construct(
        private AuthModelRegistry $models,
        private InvitationRegistrationMapper $registration,
        private PrincipalAttributeMapper $attributes,
    ) {}

    /** {@inheritDoc} */
    public function resolve(Invitation $invitation, array $input): Authenticatable
    {
        $email = mb_strtolower(trim($invitation->recipient));
        $class = $this->models->userClass();
        $existing = $class::query()
            ->where($this->attributes->column(PrincipalAttribute::Email), $email)
            ->first();

        if ($existing instanceof User) {
            return $existing;
        }

        return $class::query()->create($this->registration->map($invitation, $input));
    }
}
