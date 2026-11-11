<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Closure;

/**
 * Shares schema catalog probe results inside one authentication operation.
 *
 * Outside an operation every probe runs fresh, and results are discarded when the operation ends, so
 * nothing is cached across operations or requests.
 *
 * @internal
 */
final class AuthSchemaProbes
{
    /** @var array<string, bool>|null */
    private ?array $results = null;

    /**
     * Run one operation whose identical probes are answered once.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $operation
     * @return TResult
     */
    public function during(Closure $operation): mixed
    {
        if ($this->results !== null) {
            return $operation();
        }
        $this->results = [];
        try {
            return $operation();
        } finally {
            $this->results = null;
        }
    }

    /**
     * Answer a probe, reusing the result already read by the current operation.
     *
     * @param  Closure(): bool  $probe
     */
    public function once(string $key, Closure $probe): bool
    {
        if ($this->results === null) {
            return $probe();
        }

        return $this->results[$key] ??= $probe();
    }
}
