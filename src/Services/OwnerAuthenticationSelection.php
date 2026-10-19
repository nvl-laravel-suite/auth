<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\OwnerAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Ownership\AuthOwnerAccess;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Ownership\Contracts\OwnerAccess;
use Nvl\Ownership\Services\OwnerIdentityResolver;
use Nvl\Support\Ownership\Exceptions\OwnershipException;

/** Verifies owner selection after global authentication without entering a privileged execution scope. @internal */
final readonly class OwnerAuthenticationSelection
{
    public function __construct(private Container $container, private AuthAuditRecorder $audits) {}

    public function select(Authenticatable $subject, ?AuthenticationRequestContext $context, OwnerAuthenticationPurpose $purpose): void
    {
        if (config('nvl-auth.ownership.scoped') !== true || $context?->ownerIntentNonce === null) {
            return;
        }
        $reference = SubjectReference::fromAuthenticatable($subject);
        try {
            if ($context->ownerSessionBinding === null || $context->requestedOwner === null
                || ($context->ownerPurpose !== null && $context->ownerPurpose !== $purpose)) {
                throw new AuthException('owner_authentication_intent_invalid', 'The owner selection proof is invalid.', 410);
            }
            $owner = $this->container->make(OwnerAuthenticationIntents::class)->consume($context->ownerIntentNonce, $purpose, $context->ownerSessionBinding, $context->requestedOwner, $context->ownerIntentSubjectBound ? $reference : null);
            $canonical = $this->container->make(OwnerIdentityResolver::class)->resolve($owner);
            $access = config('nvl-auth.features.memberships.enabled') === true ? AuthOwnerAccess::class : OwnerAccess::class;
            $this->container->make($access)->assertCanEnter($subject, $canonical);
            $this->audits->record('authentication.owner_selected', subject: $reference, actor: $subject, metadata: ['owner' => $owner->toArray()]);
        } catch (AuthException|OwnershipException) {
            $this->audits->record('authentication.owner_selection_denied', outcome: 'denied', subject: $reference, actor: $subject);
        }
    }
}
