<?php

declare(strict_types=1);

namespace Nvl\Auth\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Str;
use Nvl\Auth\Services\AuthMaintenance;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Prunes terminal Auth state on an operator-controlled schedule.
 */
final class PruneAuthStateCommand extends Command
{
    /** @var string */
    protected $signature = 'nvl:auth:prune {--dry-run : Count terminal records without deleting them} {--reason=Scheduled Auth retention} {--correlation= : Trace identifier}';

    /** @var string */
    protected $description = 'Prune terminal NVL Auth state after its retention window';

    /**
     * Execute the pruning command.
     */
    public function handle(AuthMaintenance $action): int
    {
        $execute = fn (): array => $action->prune(new SystemMutationContext((string) $this->option('reason'), (string) ($this->option('correlation') ?: Str::uuid())), (bool) $this->option('dry-run'));
        $counts = $execute();
        $this->table(['State', 'Records'], array_map(static fn (string $name, int $count): array => [$name, $count], array_keys($counts), array_values($counts)));

        return self::SUCCESS;
    }
}
