<?php

declare(strict_types=1);

namespace Nvl\Auth\Console\Commands;

use Illuminate\Console\Command;
use InvalidArgumentException;
use JsonException;
use Nvl\Auth\Actions\AdoptPrincipalsAction;

/** Plans or applies manifest-driven legacy principal adoption. */
final class AdoptPrincipalsCommand extends Command
{
    /** @var string */
    protected $signature = 'nvl:auth:adopt-principals
        {manifest : Absolute or application-relative JSON manifest path}
        {--stage : Rename canonical-name legacy tables before package schema installation}
        {--apply : Apply the validated stage or import plan}
        {--format=text : Output text or json}';

    /** @var string */
    protected $description = 'Plan, stage, or apply a reconciled legacy principal adoption';

    public function handle(AdoptPrincipalsAction $adopt): int
    {
        $format = $this->option('format');

        if (! in_array($format, ['text', 'json'], true)) {
            throw new InvalidArgumentException('The nvl:auth:adopt-principals format must be text or json.');
        }

        $argument = $this->argument('manifest');

        if (trim($argument) === '') {
            throw new InvalidArgumentException('An Auth principal adoption manifest is required.');
        }

        $path = str_starts_with($argument, DIRECTORY_SEPARATOR) ? $argument : base_path($argument);
        $maximum = config('nvl-auth.adoption.maximum_manifest_bytes', 1_048_576);

        if (! is_int($maximum) || $maximum < 1) {
            throw new InvalidArgumentException('nvl-auth.adoption.maximum_manifest_bytes must be a positive integer.');
        }

        $size = is_file($path) ? filesize($path) : false;

        if (! is_int($size) || $size > $maximum) {
            throw new InvalidArgumentException("Auth principal adoption manifest [{$path}] is missing or too large.");
        }

        $contents = file_get_contents($path);

        if (! is_string($contents)) {
            throw new InvalidArgumentException("Auth principal adoption manifest [{$path}] cannot be read.");
        }

        try {
            $decoded = json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException(
                "Auth principal adoption manifest [{$path}] is not valid JSON.",
                previous: $exception,
            );
        }

        if (! is_array($decoded)) {
            throw new InvalidArgumentException('The Auth principal adoption manifest must be a JSON object.');
        }

        /** @var array<array-key, mixed> $decoded */
        $result = $adopt->execute(
            $decoded,
            stage: (bool) $this->option('stage'),
            apply: (bool) $this->option('apply'),
        );

        if ($format === 'json') {
            $this->line((string) json_encode($result, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT));

            return self::SUCCESS;
        }

        $phase = $result['phase'] ?? null;
        $mode = $result['mode'] ?? null;

        if (! is_string($phase) || ! is_string($mode)) {
            throw new InvalidArgumentException('Auth principal adoption returned an invalid result.');
        }

        $this->components->info("Auth principal {$phase} {$mode} completed.");

        return self::SUCCESS;
    }
}
