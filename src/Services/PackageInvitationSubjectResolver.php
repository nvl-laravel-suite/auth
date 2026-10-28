<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\InvitationRegistrationMapper;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\RegistrationAdmission;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Enums\PrincipalMutation;
use Nvl\Auth\Enums\RegistrationMethod;
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
        private PrincipalExtensions $extensions,
        private RegistrationAdmission $admission,
        private ConfiguredRegistrationAdmission $nativeAdmission,
    ) {}

    /** {@inheritDoc} */
    public function resolve(Invitation $invitation, #[\SensitiveParameter] array $input): Authenticatable
    {
        $class = $this->models->userClass();
        $mapped = $this->registration->map($invitation, array_diff_key($input, ['extensions' => true]));
        unset($mapped[$this->attributes->column(PrincipalAttribute::Password)]);
        $extensions = $input['extensions'] ?? [];
        if (! is_array($extensions)) {
            throw new \InvalidArgumentException('Invalid Auth input [extensions].');
        }
        $extensions = $this->extensions->map(PrincipalMutation::InvitationRegistration, $extensions, occupiedColumns: array_keys($mapped));
        $this->admission->assertAllowed(RegistrationMethod::Password, PrincipalEmailIdentity::normalize($invitation->recipient), $extensions);
        $this->nativeAdmission->assertProvisioningAllowed(invited: true);
        $mapped += $extensions;
        $user = $class::query()->create($mapped);
        if (is_string($input['password'] ?? null)) {
            $this->passwords->update($user, $input['password']);
            $user->setRememberToken(Str::random(60));
            $user->save();
        }

        return $user;
    }
}
