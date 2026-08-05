<?php

declare(strict_types=1);

namespace Nvl\Auth\Results;

/**
 * Returns one generated recovery-code batch exactly once.
 */
final readonly class GeneratedRecoveryCodes
{
    /**
     * Create a generated code result.
     *
     * @param  list<string>  $codes
     */
    public function __construct(
        public string $batchId,
        public array $codes,
    ) {}

    /**
     * Redact plaintext codes during inspection.
     *
     * @return array{batch_id: string, code_count: int}
     */
    public function __debugInfo(): array
    {
        return ['batch_id' => $this->batchId, 'code_count' => count($this->codes)];
    }
}
