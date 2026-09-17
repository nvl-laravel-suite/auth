<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Nvl\Auth\Contracts\TenantAwareAuthActivityBridge;
use Nvl\Auth\ValueObjects\AuthEventContext;

/** Captures tenant-safe Auth activity projections for integration tests. */
final class RecordingTenantAwareAuthActivityBridge implements TenantAwareAuthActivityBridge
{
    /** @var list<array{action: string, context: AuthEventContext, metadata: array<string, scalar|null>}> */
    public array $records = [];

    public function record(string $action, AuthEventContext $context, array $metadata): void
    {
        $this->records[] = compact('action', 'context', 'metadata');
    }
}
