<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Defines the establish authenticated session use-case boundary.
 *
 * @api
 */
interface EstablishAuthenticatedSessionContract
{
    /**
     * Resolve and log in a referenced host subject.
     */
    public function execute(
        SubjectReference $reference,
        bool $remember = false,
        ?AuthenticationRequestContext $requestContext = null,
        AuthenticationPurpose $purpose = AuthenticationPurpose::PasswordlessLogin,
    ): Authenticatable;
}
