<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Builder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;

/** Canonical native mailbox identity; the stored address remains a delivery/display value.
 *
 * @api
 */
final readonly class PrincipalEmailIdentity
{
    public const INDEX = 'nvl_auth_users_email_identity_hash_unique';

    public function __construct(private PrincipalAttributeMapper $attributes) {}

    public static function normalize(string $email): string
    {
        return mb_strtolower(trim($email), 'UTF-8');
    }

    public static function key(string $email): string
    {
        return hash('sha256', self::normalize($email));
    }

    /** Preserve provider hooks and non-email identifiers; native email lookup requires adopted storage.
     * External Eloquent providers retain their own identifier contract.
     *
     * @internal
     *
     * @return array<string, string>
     */
    public function credentials(UserProvider $provider, string $identifier, string $value): array
    {
        if ($identifier !== $this->attributes->column(PrincipalAttribute::Email) && $identifier !== 'email') {
            return [$identifier => $value];
        }
        if (! $provider instanceof EloquentUserProvider) {
            throw AuthException::invalidConfiguration('Canonical email lookup requires an Eloquent provider; custom providers must supply their own explicit identifier adapter.');
        }
        $model = $provider->createModel();
        if (! $model instanceof User) {
            return [$identifier => $value];
        }
        self::assertReady($model);

        return [$model->getEmailIdentityHashName() => self::key($value)];
    }

    /** Laravel Eloquent providers support query closures; keep the selected broker/provider in control.
     * External Eloquent models retain their own criteria. Other providers must supply their own broker integration.
     *
     * @internal
     *
     * @return array<string, string|\Closure>
     */
    public function brokerCredentials(string $identifier, string $value): array
    {
        if ($identifier !== $this->attributes->column(PrincipalAttribute::Email) && $identifier !== 'email') {
            return [$identifier => $value];
        }

        return [$identifier => static function (Builder $query) use ($identifier, $value): void {
            $model = $query->getModel();
            if ($model instanceof User) {
                self::assertReady($model);
                $query->where($model->getEmailIdentityHashName(), self::key($value));
            } else {
                $query->where($identifier, $value);
            }
        }];
    }

    /** Require the complete unconditional unique index and finalized non-null column.
     * @internal
     */
    public static function schemaReady(User $model): bool
    {
        $schema = $model->getConnection()->getSchemaBuilder();
        $name = $model->getTable();
        $column = $model->getEmailIdentityHashName();
        if (! $schema->hasTable($name)) {
            return false;
        }
        $definition = collect($schema->getColumns($name))->firstWhere('name', $column);

        return $definition !== null && ! $definition['nullable'] && self::indexReady($model);
    }

    /** @internal */
    public static function indexReady(User $model): bool
    {
        $schema = $model->getConnection()->getSchemaBuilder();
        $index = collect($schema->getIndexes($model->getTable()))->firstWhere('name', self::INDEX);
        if ($index === null || ! $index['unique'] || $index['columns'] !== [$model->getEmailIdentityHashName()]) {
            return false;
        }
        $connection = $model->getConnection();
        [$namespace, $table] = $schema->parseSchemaAndTable($model->getTable());
        $table = $connection->getTablePrefix().$table;

        return match ($connection->getDriverName()) {
            'pgsql' => $connection->selectFromWriteConnection('select 1 from pg_index i join pg_class t on t.oid = i.indrelid join pg_namespace n on n.oid = t.relnamespace join pg_class x on x.oid = i.indexrelid where t.relname = ? and n.nspname = coalesce(?, current_schema()) and x.relname = ? and i.indisunique and i.indisvalid and i.indisready and i.indislive and i.indimmediate and i.indpred is null and i.indexprs is null and i.indnkeyatts = 1 and i.indnatts = 1', [$table, $namespace, self::INDEX]) !== [],
            'sqlite' => $connection->selectFromWriteConnection('select 1 from pragma_index_list(?, ?) where name = ? and partial = 0', [$table, $namespace ?? 'main', self::INDEX]) !== [],
            default => true,
        };
    }

    /** @internal */
    public static function assertReady(User $model): void
    {
        if (! self::schemaReady($model)) {
            throw new AuthException('email_identity_unavailable', 'Canonical email identity requires explicit adoption and finalized schema.', 503);
        }
    }
}
