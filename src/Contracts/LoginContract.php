<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\LoginData;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use SensitiveParameter;

/**
 * Defines the login use-case boundary.
 *
 * @api
 */
interface LoginContract
{
    /**
     * Authenticate one identifier and regenerate the Laravel session identifier.
     */
    public function execute(
        #[SensitiveParameter] LoginData $data,
        ?AuthenticationRequestContext $requestContext = null,
    ): Authenticatable;
}
