<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\FeatureDefinition;

/**
 * Provides the closed, authoritative catalog of package capabilities.
 *
 * @internal
 */
final class FeatureManifest
{
    /**
     * Return every feature definition keyed by feature value.
     *
     * @return array<string, FeatureDefinition>
     */
    public function definitions(): array
    {
        $managementAbilities = new AuthManagementAbilityCatalog;
        $all = [
            FeatureOperation::Read,
            FeatureOperation::Enroll,
            FeatureOperation::Issue,
            FeatureOperation::Use,
            FeatureOperation::Update,
            FeatureOperation::Revoke,
            FeatureOperation::Cleanup,
        ];
        $readWrite = [
            FeatureOperation::Read,
            FeatureOperation::Issue,
            FeatureOperation::Use,
            FeatureOperation::Update,
            FeatureOperation::Revoke,
            FeatureOperation::Cleanup,
        ];
        $definitions = [
            new FeatureDefinition(AuthFeature::Registration, [FeatureOperation::Read, FeatureOperation::Issue], [AuthFeature::Authentication, AuthFeature::PrincipalManagement]),
            new FeatureDefinition(AuthFeature::Authentication,
                $readWrite, ),
            new FeatureDefinition(AuthFeature::PrincipalManagement,
                $all,
                managementAbilities: $managementAbilities->abilitiesFor(AuthFeature::PrincipalManagement), ),
            new FeatureDefinition(AuthFeature::Memberships,
                $all,
                [AuthFeature::Audit],
                managementAbilities: $managementAbilities->abilitiesFor(AuthFeature::Memberships), ),
            new FeatureDefinition(AuthFeature::Password,
                $readWrite,
                [AuthFeature::Authentication], ),
            new FeatureDefinition(AuthFeature::EmailVerification,
                $readWrite,
                [AuthFeature::Authentication], ),
            new FeatureDefinition(AuthFeature::MagicLinks,
                $readWrite,
                [AuthFeature::Authentication], ),
            new FeatureDefinition(AuthFeature::SecurityCodes,
                $readWrite,
                [AuthFeature::Authentication], ),
            new FeatureDefinition(AuthFeature::Invitations,
                $readWrite,
                managementAbilities: $managementAbilities->abilitiesFor(AuthFeature::Invitations), ),
            new FeatureDefinition(AuthFeature::Totp,
                $all,
                [AuthFeature::Authentication], ),
            new FeatureDefinition(AuthFeature::Passkeys,
                $all,
                [AuthFeature::Authentication], ),
            new FeatureDefinition(AuthFeature::RecoveryCodes,
                $all,
                [AuthFeature::Authentication], ),
            new FeatureDefinition(AuthFeature::SocialIdentities,
                $all,
                [AuthFeature::Authentication], ),
            new FeatureDefinition(AuthFeature::Clients,
                $readWrite,
                [AuthFeature::Authentication],
                managementAbilities: $managementAbilities->abilitiesFor(AuthFeature::Clients), ),
            new FeatureDefinition(AuthFeature::Sessions,
                [FeatureOperation::Read, FeatureOperation::Use, FeatureOperation::Revoke],
                [AuthFeature::Authentication], ),
            new FeatureDefinition(AuthFeature::ApiTokens,
                $readWrite,
                [AuthFeature::Authentication], ),
            new FeatureDefinition(AuthFeature::Rbac,
                $all,
                managementAbilities: $managementAbilities->abilitiesFor(AuthFeature::Rbac), ),
            new FeatureDefinition(AuthFeature::Audit,
                [FeatureOperation::Read, FeatureOperation::Issue, FeatureOperation::Cleanup],
                managementAbilities: $managementAbilities->abilitiesFor(AuthFeature::Audit), ),
        ];

        return array_combine(
            array_map(static fn (FeatureDefinition $definition): string => $definition->feature->value, $definitions),
            $definitions,
        );
    }

    /**
     * Return one required feature definition.
     */
    public function definition(AuthFeature $feature): FeatureDefinition
    {
        return $this->definitions()[$feature->value]
            ?? throw AuthException::invalidConfiguration("Unknown Auth feature [{$feature->value}].");
    }
}
