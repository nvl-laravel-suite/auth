<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Laravel\Sanctum\PersonalAccessToken;

/**
 * Represents a preconfigured host-owned Sanctum token model.
 */
final class HostPersonalAccessToken extends PersonalAccessToken
{
    /** @var string */
    protected $table = 'host_personal_access_tokens';
}
