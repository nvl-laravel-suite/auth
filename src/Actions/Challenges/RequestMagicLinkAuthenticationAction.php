<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Challenges;

use Nvl\Auth\Contracts\AuthIdentifierResolver;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Results\IssuedChallenge;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Requests an account-bound magic link without disclosing account existence.
 *
 * Delegation to RequestMagicLinkAction is deliberate domain orchestration: this
 * public authentication workflow resolves the subject while the canonical
 * issuance Action remains the sole owner of challenge creation and delivery.
 */
final readonly class RequestMagicLinkAuthenticationAction
{
    /**
     * Create the account-bound magic-link use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private AuthIdentifierResolver $identifiers,
        private RequestMagicLinkAction $links,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Resolve an eligible subject and issue a bound login link when one exists.
     */
    public function execute(string $identifier, ?string $locale = null): ?IssuedChallenge
    {
        $this->features->assertAllowed(AuthFeature::MagicLinks, FeatureOperation::Issue);
        $identifierName = $this->configuration->string('identifier', 'email');
        $subject = $this->identifiers->resolve($identifierName, $identifier);

        if ($subject === null) {
            $this->audits->record('magic_links.requested', metadata: ['matched' => false]);

            return null;
        }

        $reference = SubjectReference::fromAuthenticatable($subject);
        $issued = $this->links->execute(
            $identifier,
            subject: $reference,
            locale: $locale,
        );
        $this->audits->record(
            'magic_links.requested',
            subject: $reference,
            metadata: ['matched' => true, 'challenge_id' => $issued->challenge->identifier()],
        );

        return $issued;
    }
}
