<?php

declare(strict_types=1);

namespace Nvl\Auth\Console\Commands;

use Illuminate\Console\Command;
use Nvl\Auth\Services\AuthDoctor;

/**
 * Renders the package-owned read-only installation diagnostics.
 */
final class AuthDoctorCommand extends Command
{
    protected $signature = 'nvl:auth:doctor
        {--strict : Fail for configured integrations owned by disabled features}
        {--format=text : Output format: text or json}';

    /** @var string */
    protected $description = 'Validate NVL Auth schema and enabled feature readiness';

    /**
     * Execute package readiness diagnostics.
     */
    public function handle(AuthDoctor $doctor): int
    {

        $format = $this->option('format');

        if (! is_string($format) || ! in_array($format, ['text', 'json'], true)) {
            $this->components->error('The --format option must be text or json.');

            return self::INVALID;
        }

        $strict = (bool) $this->option('strict');
        $checks = $doctor->inspect($strict);

        $failed = count(array_filter(
            $checks,
            static fn (array $check): bool => ! $check['passed']
                && ($check['severity'] === 'error' || $strict),
        ));

        if ($format === 'json') {
            $this->line((string) json_encode(['ready' => $failed === 0, 'checks' => $checks], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
        } else {
            $this->table(['Check', 'Severity', 'Result', 'Message'], array_map(static fn (array $check): array => [
                $check['name'],
                $check['severity'],
                $check['passed'] ? 'PASS' : 'FAIL',
                $check['message'],
            ], $checks));
        }

        return $failed === 0 ? self::SUCCESS : self::FAILURE;
    }
}
