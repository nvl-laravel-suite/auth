<?php

declare(strict_types=1);

namespace Nvl\Auth\Console\Commands;

use Illuminate\Console\Command;
use Nvl\Auth\Actions\PruneAuthStateAction;
use Nvl\Tenancy\Services\TenantRunner;
use Nvl\Tenancy\ValueObjects\PlatformOperation;
use Nvl\Tenancy\ValueObjects\TenantId;

/**
 * Prunes terminal Auth state on an operator-controlled schedule.
 */
final class PruneAuthStateCommand extends Command
{
    /** @var string */
    protected $signature = 'nvl:auth:prune
        {--dry-run : Count terminal records without deleting them}
        {--tenant= : Prune one explicit tenant UUID}
        {--platform : Prune platform-owned and global identity history}
        {--actor-type=system : Platform operation actor type}
        {--actor-id=auth-pruner : Platform operation actor identifier}
        {--purpose=auth.prune : Platform operation purpose}';

    /** @var string */
    protected $description = 'Prune terminal NVL Auth state after its retention window';

    /**
     * Execute the pruning command.
     */
    public function handle(PruneAuthStateAction $action, TenantRunner $tenants): int
    {
        $execute = fn (): array => $action->execute((bool) $this->option('dry-run'));
        if (config('tenancy.enabled') === true) {
            $tenant = $this->option('tenant');
            $platform = (bool) $this->option('platform');
            $tenantProvided = is_string($tenant) && $tenant !== '';
            if ($tenantProvided === $platform) {
                $this->components->error('Tenant-aware pruning requires exactly one of --tenant or --platform.');

                return self::INVALID;
            }
            $counts = $platform
                ? $tenants->platform(new PlatformOperation(
                    (string) $this->option('purpose'),
                    (string) $this->option('actor-type'),
                    (string) $this->option('actor-id'),
                ), $execute)
                : $tenants->run(new TenantId((string) $tenant), $execute);
        } else {
            $counts = $execute();
        }
        $this->table(['State', 'Records'], array_map(
            static fn (string $name, int $count): array => [$name, $count],
            array_keys($counts),
            array_values($counts),
        ));

        return self::SUCCESS;
    }
}
