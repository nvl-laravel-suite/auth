<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Challenges;

use Nvl\Auth\Contracts\AuthIdentifierResolver;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Data\Mutations\RequestSecurityCodeData;
use Nvl\Auth\Enums\TenantAuthenticationPurpose;
use Nvl\Auth\Results\IssuedChallenge;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\TenantAuthenticationChallengeIntents;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\ValueObjects\TenantId;

/** Resolves and issues a subject-bound security code for public authentication. */
final readonly class RequestSecurityCodeAuthenticationAction
{
    public function __construct(
        private AuthConfiguration $configuration,
        private PrincipalAttributeMapper $principalAttributes,
        private AuthIdentifierResolver $identifiers,
        private RequestSecurityCodeAction $codes,
        private TenantAuthenticationChallengeIntents $tenantIntents,
    ) {}

    public function execute(
        RequestSecurityCodeData $data,
        ?string $locale = null,
        ?TenantId $tenant = null,
    ): ?IssuedChallenge {
        $identifierName = $this->principalAttributes->identifierColumn(
            $this->configuration->string('identifier', 'email'),
        );
        $subject = $this->identifiers->resolve($identifierName, $data->recipient);
        if ($subject === null) {
            return null;
        }

        $reference = SubjectReference::fromAuthenticatable($subject);
        $issued = $this->codes->execute($data, $reference, locale: $locale);
        $this->tenantIntents->attach(
            $issued->challenge,
            $tenant,
            TenantAuthenticationPurpose::SecurityCode,
            'security_code',
            $reference,
        );

        return $issued;
    }
}
