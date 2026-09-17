<?php

declare(strict_types=1);

namespace Nvl\Auth\Relations;

use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Database\Grammar;

/**
 * Internal PostgreSQL expression comparing text storage with a grammar-wrapped typed column.
 *
 * @internal
 */
final readonly class TextCastColumnComparison implements Expression
{
    public function __construct(
        private string $textColumn,
        private string $typedColumn,
    ) {}

    public function getValue(Grammar $grammar): string
    {
        return "{$this->textColumn} = CAST({$this->typedColumn} AS TEXT)";
    }
}
