<?php

declare(strict_types=1);

namespace Nvl\Auth\Results;

use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;

/** Carries a verified passkey subject and its server-owned tenant intent context. */
final readonly class CompletedPasskeyAuthentication
{
    public function __construct(
        public SubjectReference $subject,
        public ?AuthenticationRequestContext $requestContext,
    ) {}
}
