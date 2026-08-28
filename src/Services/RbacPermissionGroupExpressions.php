<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Expression;
use Illuminate\Database\Query\Grammars\MySqlGrammar;
use Illuminate\Database\Query\Grammars\SqlServerGrammar;
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

        if ($grammar instanceof MySqlGrammar) {
            return "TRIM(COALESCE(`group`, ''))";
        }

        if ($grammar instanceof SqlServerGrammar) {
            return "TRIM(COALESCE([group], ''))";
        }

        return "TRIM(COALESCE(\"group\", ''))";
    }

    /**
     * Return the grammar-specific normalized-group SQL.
     *
     * @param  Builder<Permission>  $query
     * @return literal-string
     */
    private function normalizedSql(Builder $query): string
    {
        $grammar = $query->getQuery()->getGrammar();

        if ($grammar instanceof MySqlGrammar) {
            return "COALESCE(NULLIF(TRIM(`group`), ''), 'general')";
        }

        if ($grammar instanceof SqlServerGrammar) {
            return "COALESCE(NULLIF(TRIM([group]), ''), 'general')";
        }

        return "COALESCE(NULLIF(TRIM(\"group\"), ''), 'general')";
    }

    /**
     * Return the grammar-specific normalized-group selection SQL.
     *
     * @param  Builder<Permission>  $query
     * @return literal-string
     */
    private function selectedSql(Builder $query): string
    {
        $grammar = $query->getQuery()->getGrammar();

        if ($grammar instanceof MySqlGrammar) {
            return "COALESCE(NULLIF(TRIM(`group`), ''), 'general') AS `normalized_group`";
        }

        if ($grammar instanceof SqlServerGrammar) {
            return "COALESCE(NULLIF(TRIM([group]), ''), 'general') AS [normalized_group]";
        }

        return "COALESCE(NULLIF(TRIM(\"group\"), ''), 'general') AS \"normalized_group\"";
    }
}
