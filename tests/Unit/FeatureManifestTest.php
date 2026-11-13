<?php

declare(strict_types=1);

use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\FeatureManifest;

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

it('requires audit before admitting membership mutations', function (): void {
    config()->set('nvl-auth.features.memberships.enabled', true);
    config()->set('nvl-auth.features.audit.enabled', false);

    expect(app(FeatureGate::class)->allows(AuthFeature::Memberships, FeatureOperation::Enroll))
        ->toBeFalse();

    try {
        app(FeatureGate::class)->assertAllowed(AuthFeature::Memberships, FeatureOperation::Enroll);
    } catch (AuthException $exception) {
        expect($exception->context['dependencies'] ?? null)->toBe(['audit']);

        return;
    }

    $this->fail('Membership admission did not report its missing audit dependency.');
});

it('keeps native feature contracts and consumer route fixtures aligned', function (): void {
    $configuration = require dirname(__DIR__, 2).'/config/nvl-auth.php';
    $definitions = app(FeatureManifest::class)->definitions();
    $features = array_map(static fn (AuthFeature $feature): string => $feature->value, AuthFeature::cases());
    expect(array_keys($configuration['features']))->toBe($features)
        ->and(array_keys($definitions))->toBe($features);
    foreach ($configuration['features'] as $settings) {
        expect($settings['enabled'])->toBeBool()->and($settings['settings'])->toBeArray()->and($settings)->not->toHaveKey('routes');
    }
    foreach (app(Nvl\Auth\Tests\Fixtures\Consumer\FeatureManifest::class)->definitions() as $definition) {
        foreach ($definition->routeFamilies as $surface => $family) {
            $contents = file_get_contents(dirname(__DIR__)."/Fixtures/Consumer/routes/{$surface}/{$family}.php");
            expect($contents)->toBeString();
            preg_match_all("/->name\\('([^']+)'\\)/", $contents, $routeNames);
            expect($routeNames[1] ?? [])->toBe($definition->routeNames[$surface]);
        }
        $native = $definitions[$definition->feature->value];
        expect($native->operations)->toBe($definition->operations)->and($native->managementAbilities)->toBe($definition->managementAbilities);
    }
});

it('rejects the former scalar feature configuration with an actionable error', function (): void {
    config()->set('nvl-auth.features.magic_links', 'enabled');

    expect(fn () => app(FeatureGate::class)->assertAllowed(AuthFeature::MagicLinks, FeatureOperation::Issue))
        ->toThrow(AuthException::class, 'must define a boolean [enabled] flag');
});
