<?php

declare(strict_types=1);

namespace Nvl\Auth\Support;

use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Grammar;

/**
 * Matches untrusted search text literally inside portable LIKE predicates.
 *
 * @internal
 */
final readonly class LiteralSearch implements Expression
{
    private function __construct(private string $column) {}

    /**
     * Constrain a query to rows where any listed column contains the literal text.
     *
     * @param  Builder<*>  $query
     * @param  list<string>  $columns
     */
    public static function contains(Builder $query, array $columns, string $search): void
    {
        $pattern = '%'.str_replace(['!', '%', '_'], ['!!', '!%', '!_'], $search).'%';
        $query->where(static function (Builder $nested) use ($columns, $pattern): void {
            foreach ($columns as $column) {
                $nested->getQuery()->whereRaw(new self($column), [$pattern], 'or');
            }
        });
    }

    /** Render one grammar-wrapped column compared with an explicitly escaped pattern. */
    public function getValue(Grammar $grammar): string
    {
        return $grammar->wrap($this->column)." like ? escape '!'";
    }
}
