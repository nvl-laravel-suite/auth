<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Nvl\Auth\Models\PersonalAccessToken;

/** Extends native Sanctum storage while retaining its immutable owner and principal binding. */
final class ConfiguredOwnerToken extends PersonalAccessToken {}
