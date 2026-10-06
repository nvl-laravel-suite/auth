<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Data\Mutations\RequestSecurityCodeData;
use Nvl\Auth\Results\IssuedChallenge;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Defines the request security code use-case boundary.
 *
 * @api
 */
interface RequestSecurityCodeContract
{
    /**
     * Issue one security code.
     *
     * @param  array<string, mixed>  $payload
     */
    public function execute(
        RequestSecurityCodeData $data,
        ?SubjectReference $subject = null,
        array $payload = [],
        ?string $locale = null,
    ): IssuedChallenge;
}
