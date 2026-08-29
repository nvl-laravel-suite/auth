<?php

declare(strict_types=1);

namespace Nvl\Auth\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Foundation\Application;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIntegrationPreset;
use RuntimeException;
use Throwable;

/**
 * Generates a safe Auth configuration overlay for one consumer preset.
 */
final class AuthConfigureCommand extends Command
{
    /** @var string */
    protected $signature = 'nvl:auth:configure
        {--preset= : Integration preset}
        {--user-model= : Host principal model class}
        {--enable=* : Explicitly enable one Auth feature}
        {--disable=* : Explicitly disable one Auth feature}
        {--path= : Destination inside the application; defaults to config/nvl-auth.php}
        {--write : Atomically write the destination instead of previewing it}
        {--force : Allow --write to replace an existing file after reviewing a dry-run diff}
        {--format=text : Output format: text or json}';

    /** @var string */
    protected $description = 'Preview or write a focused NVL Auth consumer configuration';

    /**
     * Preview or write an Auth integration overlay.
     */
    public function handle(Application $application, Filesystem $filesystem): int
    {
        $format = $this->option('format');
        $preset = $this->option('preset');
        $userModel = $this->option('user-model');
        $enabled = $this->option('enable');
        $disabled = $this->option('disable');
        $write = (bool) $this->option('write');
        $force = (bool) $this->option('force');

        if (! in_array($format, ['text', 'json'], true)) {
            return $this->invalid('The --format option must be text or json.');
        }

        if ($preset !== AuthIntegrationPreset::EmbeddedApplication->value) {
            return $this->invalid(sprintf(
                'The --preset option must be %s.',
                AuthIntegrationPreset::EmbeddedApplication->value,
            ));
        }

        if (! is_string($userModel)
            || preg_match('/\A(?:[A-Za-z_][A-Za-z0-9_]*\\\\)*[A-Za-z_][A-Za-z0-9_]*\z/', $userModel) !== 1) {
            return $this->invalid('The --user-model option must be a valid class name.');
        }

        if ($force && ! $write) {
            return $this->invalid('The --force option may only be used with --write.');
        }

        try {
            /** @var array<mixed> $enabled */
            /** @var array<mixed> $disabled */
            $featureOverrides = $this->featureOverrides($enabled, $disabled);
            $path = $this->resolvePath($application, $filesystem, $this->option('path'));
            $contents = $this->render($userModel, $featureOverrides);
            $diff = $this->diff($filesystem, $path, $contents);
        } catch (Throwable $throwable) {
            return $this->invalid($throwable->getMessage());
        }

        if ($format === 'text' && is_string($diff) && $diff !== '') {
            $this->line($diff);
        }

        if ($write && $diff !== null && ! $force) {
            return $this->invalid('The Auth configuration already exists; pass --force to replace it.');
        }

        if ($write) {
            try {
                $filesystem->replace($path, $contents);
            } catch (Throwable) {
                $this->components->error('The Auth configuration could not be written.');

                return self::FAILURE;
            }
        }

        $report = [
            'preset' => $preset,
            'path' => $this->relativePath($application, $path),
            'write_requested' => $write,
            'written' => $write,
            'features' => $featureOverrides,
            'contents' => $contents,
            'diff' => $diff,
        ];

        if ($format === 'json') {
            $this->line((string) json_encode(
                $report,
                JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
            ));

            return self::SUCCESS;
        }

        $this->components->info($write
            ? sprintf('Wrote [%s].', $report['path'])
            : sprintf('Dry run for [%s]; pass --write to create it.', $report['path']));

        $this->line($contents);

        return self::SUCCESS;
    }

    /**
     * Validate repeatable feature overrides.
     *
     * @param  array<mixed>  $enabled
     * @param  array<mixed>  $disabled
     * @return array<string, bool>
     */
    private function featureOverrides(array $enabled, array $disabled): array
    {
        $known = array_column(AuthFeature::cases(), 'value');
        $overrides = [];

        foreach ([[true, $enabled], [false, $disabled]] as [$state, $features]) {
            foreach ($features as $feature) {
                if (! is_string($feature) || ! in_array($feature, $known, true)) {
                    throw new RuntimeException(sprintf(
                        'Feature overrides must use one of: %s.',
                        implode(', ', $known),
                    ));
                }

                if (array_key_exists($feature, $overrides) && $overrides[$feature] !== $state) {
                    throw new RuntimeException("Auth feature [{$feature}] cannot be both enabled and disabled.");
                }

                $overrides[$feature] = $state;
            }
        }

        uksort($overrides, static fn (string $left, string $right): int => array_search($left, $known, true) <=> array_search($right, $known, true));

        return $overrides;
    }

    /**
     * Render the minimal embedded-application overlay.
     *
     * @param  array<string, bool>  $featureOverrides
     */
    private function render(string $userModel, array $featureOverrides): string
    {
        $features = [
            "        'principal_management' => [\n            'models' => ['user' => \\{$userModel}::class],\n        ],",
        ];

        foreach ($featureOverrides as $feature => $enabled) {
            if ($feature === AuthFeature::PrincipalManagement->value) {
                $features[0] = sprintf(
                    "        'principal_management' => [\n            'enabled' => %s,\n            'models' => ['user' => \\%s::class],\n        ],",
                    $enabled ? 'true' : 'false',
                    $userModel,
                );

                continue;
            }

            $features[] = sprintf(
                "        '%s' => ['enabled' => %s],",
                $feature,
                $enabled ? 'true' : 'false',
            );
        }

        return sprintf(
            <<<'PHP'
<?php

declare(strict_types=1);

use Nvl\Auth\Services\ConfiguredPolicyAuthManagementAccess;

return [
    'ownership' => [
        'http' => 'host',
        'delivery' => 'host',
    ],

    'services' => [
        'management_access' => ConfiguredPolicyAuthManagementAccess::class,
    ],

    'features' => [
%s
    ],

    'routes' => [
        'enabled' => false,
        'public' => ['enabled' => false],
        'account' => ['enabled' => false],
        'management' => ['enabled' => false],
    ],
];

PHP,
            implode("\n", $features),
        );
    }

    /**
     * Resolve a PHP destination contained by the application root.
     */
    private function resolvePath(
        Application $application,
        Filesystem $filesystem,
        mixed $path,
    ): string {
        if ($path !== null && (! is_string($path) || trim($path) === '')) {
            throw new RuntimeException('The Auth configuration path must be a non-empty string.');
        }

        $root = realpath($application->basePath());
        $candidate = is_string($path) ? $path : $application->configPath('nvl-auth.php');

        if ($root === false) {
            throw new RuntimeException('The application root could not be resolved.');
        }

        if (! str_starts_with($candidate, DIRECTORY_SEPARATOR)) {
            $candidate = $root.DIRECTORY_SEPARATOR.$candidate;
        }

        $candidate = $this->normalizePath($candidate);

        if (strtolower(pathinfo($candidate, PATHINFO_EXTENSION)) !== 'php') {
            throw new RuntimeException('The Auth configuration path must use the .php extension.');
        }

        $parent = realpath(dirname($candidate));

        if ($parent === false
            || ! is_dir($parent)
            || ! $this->within($root, $parent)
            || ! $this->within($root, $candidate)) {
            throw new RuntimeException('The Auth configuration path must be inside the application root with an existing parent directory.');
        }

        if ($filesystem->exists($candidate)) {
            $resolved = realpath($candidate);

            if (! $filesystem->isFile($candidate)
                || ! $filesystem->isReadable($candidate)
                || $resolved === false
                || ! $this->within($root, $resolved)) {
                throw new RuntimeException('The existing Auth configuration must be a readable in-application file.');
            }
        }

        return $candidate;
    }

    /**
     * Collapse current- and parent-directory path segments.
     */
    private function normalizePath(string $path): string
    {
        $parts = [];

        foreach (explode(DIRECTORY_SEPARATOR, $path) as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }

            if ($part === '..') {
                array_pop($parts);

                continue;
            }

            $parts[] = $part;
        }

        return DIRECTORY_SEPARATOR.implode(DIRECTORY_SEPARATOR, $parts);
    }

    /**
     * Determine whether one path is contained by a canonical base path.
     */
    private function within(string $base, string $path): bool
    {
        return $path === $base || str_starts_with($path, rtrim($base, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR);
    }

    /**
     * Render a reviewable unified diff when a destination already exists.
     */
    private function diff(Filesystem $filesystem, string $path, string $contents): ?string
    {
        if (! $filesystem->exists($path)) {
            return null;
        }

        $current = $filesystem->get($path);

        if ($current === $contents) {
            return '';
        }

        $currentLines = explode("\n", rtrim($current, "\n"));
        $generatedLines = explode("\n", rtrim($contents, "\n"));
        $name = basename($path);

        return implode("\n", [
            '--- config/'.$name,
            '+++ generated/'.$name,
            sprintf('@@ -1,%d +1,%d @@', count($currentLines), count($generatedLines)),
            ...array_map(static fn (string $line): string => '-'.$line, $currentLines),
            ...array_map(static fn (string $line): string => '+'.$line, $generatedLines),
            '',
        ]);
    }

    /**
     * Return an application-relative path suitable for diagnostics.
     */
    private function relativePath(Application $application, string $path): string
    {
        $root = rtrim($application->basePath(), DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;

        return str_starts_with($path, $root) ? substr($path, strlen($root)) : basename($path);
    }

    /**
     * Render one validation error.
     */
    private function invalid(string $message): int
    {
        $this->components->error($message);

        return self::INVALID;
    }
}
