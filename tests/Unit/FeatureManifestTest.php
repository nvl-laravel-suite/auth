<?php

declare(strict_types=1);

use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\FeatureManifest;

it('defines every supported feature exactly once', function (): void {
    $definitions = app(FeatureManifest::class)->definitions();

    expect($definitions)
        ->toHaveCount(16)
        ->and(array_keys($definitions))->toBe(array_map(
            static fn (AuthFeature $feature): string => $feature->value,
            AuthFeature::cases(),
        ));
});

it('fails disabled functionality closed while retaining containment operations', function (): void {
    config()->set('nvl-auth.features.invitations.enabled', false);
    $gate = app(FeatureGate::class);

    expect($gate->allows(AuthFeature::Invitations, FeatureOperation::Issue))->toBeFalse()
        ->and($gate->allows(AuthFeature::Invitations, FeatureOperation::Revoke))->toBeTrue()
        ->and(fn () => $gate->assertAllowed(AuthFeature::Invitations, FeatureOperation::Issue))
        ->toThrow(AuthException::class, 'unavailable');
});

it('requires explicit dependencies without auto enabling them', function (): void {
    config()->set('nvl-auth.features.authentication.enabled', false);
    config()->set('nvl-auth.features.password.enabled', true);

    expect(app(FeatureGate::class)->allows(AuthFeature::Password, FeatureOperation::Use))
        ->toBeFalse();
});

it('keeps configuration and route files aligned with the closed feature manifest', function (): void {
    $configuration = require dirname(__DIR__, 2).'/config/nvl-auth.php';
    $expectedFeatures = array_map(
        static fn (AuthFeature $feature): string => $feature->value,
        AuthFeature::cases(),
    );

    expect(array_keys($configuration['features']))->toBe($expectedFeatures);

    foreach ($configuration['features'] as $feature => $settings) {
        expect($settings)->toBeArray()
            ->and(array_keys($settings))->each->toBeIn(['enabled', 'routes', 'services', 'models', 'settings'])
            ->and($settings['enabled'])->toBeBool()
            ->and($settings['routes'])->toBeArray()
            ->and($settings['settings'])->toBeArray();

        foreach ($settings['routes'] as $surface => $routeSettings) {
            expect($surface)->toBeIn(['public', 'account', 'management'])
                ->and($routeSettings)->toBeArray()
                ->and($routeSettings['enabled'])->toBeBool();
        }
    }

    foreach (app(FeatureManifest::class)->definitions() as $definition) {
        foreach ($definition->routeFamilies as $surface => $family) {
            $path = dirname(__DIR__, 2)."/routes/{$surface}/{$family}.php";
            $contents = file_get_contents($path);

            expect($contents)->toBeString();
            preg_match_all("/->name\\('([^']+)'\\)/", (string) $contents, $routeNames);

            expect($routeNames[1] ?? [])->toBe($definition->routeNames[$surface]);
        }

        if (array_key_exists('management', $definition->routeFamilies)) {
            expect($definition->managementAbilities, $definition->feature->value)->not->toBeEmpty();
        } else {
            expect($definition->managementAbilities, $definition->feature->value)->toBeEmpty();
        }
    }
});

it('keeps feature admission as the first statement of every public Action', function (): void {
    $directory = dirname(__DIR__, 2).'/src/Actions';
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));

    foreach ($files as $file) {
        if (! $file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }

        $contents = file_get_contents($file->getPathname());

        expect($contents)->toBeString();
        preg_match(
            '/public function execute[\\s\\S]*?\\)\\s*:\\s*[^\\{]+\\{\\s*(?<first>[^\\r\\n]+)/',
            (string) $contents,
            $method,
        );

        expect($method['first'] ?? null, $file->getFilename())
            ->toStartWith('$this->features->assertAllowed(');
    }
});

it('rejects the former scalar feature configuration with an actionable error', function (): void {
    config()->set('nvl-auth.features.magic_links', 'enabled');

    expect(fn () => app(FeatureGate::class)->assertAllowed(AuthFeature::MagicLinks, FeatureOperation::Issue))
        ->toThrow(AuthException::class, 'must define a boolean [enabled] flag');
});

it('keeps Actions and Services independent from HTTP transport classes', function (): void {
    foreach (['Actions', 'Services'] as $layer) {
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(
            dirname(__DIR__, 2)."/src/{$layer}",
        ));

        foreach ($files as $file) {
            if (! $file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            $contents = file_get_contents($file->getPathname());

            expect($contents)->toBeString()
                ->and($contents, $file->getFilename())->not->toContain('Illuminate\\Http');
        }
    }
});
