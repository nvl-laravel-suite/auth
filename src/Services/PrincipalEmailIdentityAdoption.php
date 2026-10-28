<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Database\Schema\Blueprint;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/** Explicit retained-row adoption. Drain legacy workers and disable identity writes before planning/applying.
 *
 * @api
 */
final readonly class PrincipalEmailIdentityAdoption
{
    public function __construct(private AuthModelRegistry $models, private PrincipalAttributeMapper $attributes, private MutationAuthorizer $authorization, private AuthConfiguration $configuration, private AuthAuditRecorder $audits) {}

    /** Diagnostics contain at most 20 collision groups and 20 references per group, never addresses.
     * @return array{missing: int, collisions: list<array{key: string, subjectIds: list<string>}>, ready: bool}
     */
    public function plan(): array
    {
        $class = $this->models->userClass();
        $model = new $class;
        $connection = $model->getConnection();
        $column = $model->getEmailIdentityHashName();
        $schema = $connection->getSchemaBuilder();
        if (! $schema->hasTable($model->getTable()) || ! $schema->hasColumn($model->getTable(), $column)) {
            return ['missing' => $schema->hasTable($model->getTable()) ? $connection->table($model->getTable())->count() : 0, 'collisions' => [], 'ready' => false];
        }
        $email = $this->attributes->column(PrincipalAttribute::Email);
        $id = $model->getKeyName();
        $seen = [];
        $collisions = [];
        $missing = 0;
        foreach ($connection->table($model->getTable())->useWritePdo()->orderBy($id)->cursor() as $row) {
            $emailValue = $row->{$email};
            $subjectId = $row->{$id};
            if (! is_string($emailValue) || (! is_string($subjectId) && ! is_int($subjectId))) {
                throw new AuthException('email_identity_unavailable', 'Retained identity has an unsupported email or subject reference.', 503);
            }
            $key = PrincipalEmailIdentity::key($emailValue);
            if ($row->{$column} !== $key) {
                $missing++;
            }
            if (isset($seen[$key])) {
                if (isset($collisions[$key]) || count($collisions) < 20) {
                    $collisions[$key] ??= ['key' => $key, 'subjectIds' => [$seen[$key]]];
                    if (count($collisions[$key]['subjectIds']) < 20) {
                        $collisions[$key]['subjectIds'][] = (string) $subjectId;
                    }
                }
            } else {
                $seen[$key] = (string) $subjectId;
            }
        }

        return ['missing' => $missing, 'collisions' => array_values($collisions), 'ready' => $missing === 0 && $collisions === [] && PrincipalEmailIdentity::schemaReady($model)];
    }

    /** Data commits before separately inspected DDL; MySQL DDL is never claimed rollbackable.
     * Host-owned schema receives authorized data only and must finalize independently.
     *
     * @return array{updated: int, finalized: bool}
     */
    public function apply(SystemMutationContext $authority): array
    {
        $this->authorization->authorize($authority, 'nvl.auth.users.adoptEmailIdentities');
        $class = $this->models->userClass();
        $model = new $class;
        $connection = $model->getConnection();
        if ($connection->transactionLevel() !== 0) {
            throw new AuthException('email_adoption_transaction_unsupported', 'Email adoption requires its own data commit before schema finalization.', 409);
        }
        $column = $model->getEmailIdentityHashName();
        if (! $connection->getSchemaBuilder()->hasColumn($model->getTable(), $column) || ! PrincipalEmailIdentity::indexReady($model)) {
            throw new AuthException('email_identity_unavailable', 'Run the forward email identity migration before adoption.', 503);
        }
        $email = $this->attributes->column(PrincipalAttribute::Email);
        $id = $model->getKeyName();
        $updated = $connection->transaction(function () use ($connection, $model, $column, $email, $id, $authority): int {
            $rows = $connection->table($model->getTable())->orderBy($id)->lockForUpdate()->get();
            if ($this->plan()['collisions'] !== []) {
                throw new AuthException('email_identity_collision', 'Resolve retained email identity collisions explicitly before adoption.', 409);
            }
            $updated = 0;
            foreach ($rows as $row) {
                $emailValue = $row->{$email};
                $subjectId = $row->{$id};
                if (! is_string($emailValue) || (! is_string($subjectId) && ! is_int($subjectId))) {
                    throw new AuthException('email_identity_unavailable', 'Retained identity has an unsupported email or subject reference.', 503);
                }
                $key = PrincipalEmailIdentity::key($emailValue);
                if ($row->{$column} !== $key) {
                    $updated += $connection->table($model->getTable())->where($id, $row->{$id})->update([$column => $key]);
                }
            }
            $this->audits->record('email_identity.adopted', actor: $authority->actor, metadata: [...$authority->auditMetadata(), 'updated' => $updated]);

            return $updated;
        });
        if ($this->configuration->boolean('migrations.enabled', true) && ! PrincipalEmailIdentity::schemaReady($model)) {
            $connection->getSchemaBuilder()->table($model->getTable(), fn (Blueprint $table) => $table->string($column, 64)->nullable(false)->change());
        }

        return ['updated' => $updated, 'finalized' => $this->plan()['ready']];
    }
}
