<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Closure;
use Nvl\Auth\ValueObjects\AuthPipelineContext;

/**
 * Extends one named Auth use-case pipeline.
 */
interface AuthPipelineStage
{
    /**
     * Handle one pipeline context and invoke the next stage.
     */
    public function handle(AuthPipelineContext $context, Closure $next): mixed;
}
