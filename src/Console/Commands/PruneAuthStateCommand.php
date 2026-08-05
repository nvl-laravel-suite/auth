<?php

declare(strict_types=1);

namespace Nvl\Auth\Console\Commands;

use Illuminate\Console\Command;
use Nvl\Auth\Actions\PruneAuthStateAction;

/**
 * Prunes terminal Auth state on an operator-controlled schedule.
 */
final class PruneAuthStateCommand extends Command
{
    /** @var string */
    protected $signature = 'nvl:auth:prune {--dry-run : Count terminal records without deleting them}';

    /** @var string */
    protected $description = 'Prune terminal NVL Auth state after its retention window';

    /**
     * Execute the pruning command.
     */
    public function handle(PruneAuthStateAction $action): int
    {
        $counts = $action->execute((bool) $this->option('dry-run'));
        $this->table(['State', 'Records'], array_map(
            static fn (string $name, int $count): array => [$name, $count],
            array_keys($counts),
            array_values($counts),
        ));

        return self::SUCCESS;
    }
}
