<?php

declare(strict_types=1);

namespace Nvl\Auth\Console\Commands;

use Illuminate\Console\Command;
use InvalidArgumentException;
use JsonException;
use Nvl\Auth\Services\AuthSchemaManager;

/** Plans or installs schema required by currently enabled Auth features. */
final class InstallAuthSchemaCommand extends Command
{
    /** @var string */
    protected $signature = 'nvl:auth:schema
        {--apply : Create missing tables required by enabled features}
        {--format=text : Output text or json}';

    /** @var string */
    protected $description = 'Plan or install missing schema for enabled NVL Auth features';

    /**
     * @throws JsonException
     */
    public function handle(AuthSchemaManager $schema): int
    {
        $format = $this->option('format');

        if (! in_array($format, ['text', 'json'], true)) {
            throw new InvalidArgumentException('The nvl:auth:schema format must be text or json.');
        }

        $result = $schema->execute((bool) $this->option('apply'));

        if ($format === 'json') {
            $this->line((string) json_encode($result, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT));

            return self::SUCCESS;
        }

        $this->components->info(sprintf(
            'Auth schema %s completed: %d required, %d missing, %d created.',
            $result['mode'],
            count($result['required']),
            count($result['missing']),
            count($result['created']),
        ));

        foreach ($result['missing'] as $table) {
            $this->line(" - {$table}");
        }

        return self::SUCCESS;
    }
}
