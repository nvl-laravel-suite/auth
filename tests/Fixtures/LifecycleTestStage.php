<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Closure;
use Nvl\Auth\Contracts\AuthPipelineStage;
use Nvl\Auth\ValueObjects\AuthPipelineContext;

/** A consumer pipeline stage that delegates to a test-controlled lifecycle hook. */
final class LifecycleTestStage implements AuthPipelineStage
{
    public function __construct(private Closure $callback) {}

    public function handle(AuthPipelineContext $context, Closure $next): mixed
    {
        return ($this->callback)($context, $next);
    }
}
