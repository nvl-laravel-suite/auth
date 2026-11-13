<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Expression;
use Illuminate\Database\Query\Grammars\PostgresGrammar;
use Nvl\Auth\Models\Permission;

/**
 * Builds portable permission-group expressions for supported Laravel grammars.
 *
 * @internal
 */
final class RbacPermissionGroupExpressions
{
    /**
     * Build an expression that treats null and whitespace-only groups as blank.
     *
     * @param  Builder<Permission>  $query
     * @return Expression<literal-string>
     */
    public function blank(Builder $query): Expression
    {
        return new Expression($this->blankSql($query));
    }

    /**
     * Build an expression that returns the canonical permission group.
     *
     * @param  Builder<Permission>  $query
     * @return Expression<literal-string>
     */
    public function normalized(Builder $query): Expression
    {
        return new Expression($this->normalizedSql($query));
    }

    /**
     * Build the normalized group selection with its stable result alias.
     *
     * @param  Builder<Permission>  $query
     * @return Expression<literal-string>
     */
    public function selected(Builder $query): Expression
    {
        return new Expression($this->selectedSql($query));
    }

    /**
     * Return the grammar-specific blank-group SQL.
     *
     * @param  Builder<Permission>  $query
     * @return literal-string
     */
    private function blankSql(Builder $query): string
    {
        $grammar = $query->getQuery()->getGrammar();

        if ($grammar instanceof PostgresGrammar) {
            return "BTRIM(REPLACE(REPLACE(REPLACE(REPLACE(COALESCE(\"group\", ''), CHR(9), ''), CHR(10), ''), CHR(11), ''), CHR(13), ''))";
        }

        return "TRIM(REPLACE(REPLACE(REPLACE(REPLACE(COALESCE(\"group\", ''), CHAR(9), ''), CHAR(10), ''), CHAR(11), ''), CHAR(13), ''))";
    }

    /**
     * Return the grammar-specific normalized-group SQL.
     *
     * @param  Builder<Permission>  $query
     * @return literal-string
     */
    private function normalizedSql(Builder $query): string
    {
        $blank = $this->blankSql($query);

        return "COALESCE(NULLIF({$blank}, ''), 'general')";
    }

    /**
     * Return the grammar-specific normalized-group selection SQL.
     *
     * @param  Builder<Permission>  $query
     * @return literal-string
     */
    private function selectedSql(Builder $query): string
    {
        return "{$this->normalizedSql($query)} AS \"normalized_group\"";
    }

    public static function normalize(?string $group): ?string
    {
        $group = trim(str_replace(["\t", "\n", "\v", "\r"], '', (string) $group), ' ');

        return $group !== '' ? $group : null;
    }
}
