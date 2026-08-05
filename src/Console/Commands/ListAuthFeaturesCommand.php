<?php

declare(strict_types=1);

namespace Nvl\Auth\Console\Commands;

use Illuminate\Console\Command;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\FeatureManifest;

/**
 * Displays configured and effective package capabilities.
 */
final class ListAuthFeaturesCommand extends Command
{
    /** @var string */
    protected $signature = 'nvl:auth:features {--format=table : table or json}';

    /** @var string */
    protected $description = 'Display the NVL Auth feature matrix';

    /**
     * Execute the feature inventory command.
     */
    public function handle(
        FeatureManifest $manifest,
        AuthConfiguration $configuration,
        FeatureGate $features,
    ): int {
        $format = $this->option('format');

        if (! is_string($format) || ! in_array($format, ['table', 'json'], true)) {
            $this->error('The --format option must be table or json.');

            return self::INVALID;
        }

        $rows = [];

        foreach ($manifest->definitions() as $definition) {
            $rows[] = [
                'feature' => $definition->feature->value,
                'configured' => $configuration->featureEnabled($definition->feature),
                'effective' => $features->allows($definition->feature, FeatureOperation::Read),
                'dependencies' => array_map(static fn ($dependency): string => $dependency->value, $definition->dependencies),
                'routes' => $definition->routeFamilies,
            ];
        }

        if ($format === 'json') {
            $this->line((string) json_encode($rows, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));

            return self::SUCCESS;
        }

        $this->table(
            ['Feature', 'Configured', 'Effective', 'Dependencies', 'Route surfaces'],
            array_map(static fn (array $row): array => [
                $row['feature'],
                $row['configured'] ? 'yes' : 'no',
                $row['effective'] ? 'yes' : 'no',
                implode(', ', $row['dependencies']),
                implode(', ', array_keys($row['routes'])),
            ], $rows),
        );

        return self::SUCCESS;
    }
}
