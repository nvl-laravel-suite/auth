<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Closure;
use Nvl\Auth\Contracts\AuthPipelineStage;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Captures and rejects a post-credential login pipeline in tests.
 */
final class RejectLoginStage implements AuthPipelineStage
{
    public static ?SubjectReference $subject = null;

    /** {@inheritDoc} */
    public function handle(AuthPipelineContext $context, Closure $next): mixed
    {
        self::$subject = $context->subject;

        throw new AuthException('login_rejected', 'Login policy rejected the subject.', 422);
    }
}
