<?php

declare(strict_types=1);

namespace Nvl\Auth\Traits;

use Nvl\Support\Ownership\Traits\HasOwnership;

/**
 * Applies the native ownership boundary to declared Auth resources.
 *
 * @internal
 */
trait HasAuthOwnership
{
    use HasOwnership;
}
