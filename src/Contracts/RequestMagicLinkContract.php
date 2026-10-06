<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Data\Mutations\RequestMagicLinkData;
use Nvl\Auth\Results\IssuedChallenge;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Defines the request magic link use-case boundary.
 *
 * @api
 */
interface RequestMagicLinkContract
{
    /**
     * Issue one magic link.
     *
     * @param  array<string, mixed>  $payload
     */
    public function execute(
        RequestMagicLinkData $data,
        ?SubjectReference $subject = null,
        array $payload = [],
        ?string $locale = null,
    ): IssuedChallenge;
}
