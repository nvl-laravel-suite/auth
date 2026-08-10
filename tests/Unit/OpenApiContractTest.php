<?php

declare(strict_types=1);

use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Services\FeatureManifest;

it('keeps OpenAPI operations and feature metadata identical to the manifest', function (): void {
    $contents = file_get_contents(dirname(__DIR__, 2).'/docs/openapi.json');

    if (! is_string($contents)) {
        throw new RuntimeException('OpenAPI document is unavailable.');
    }

    $document = json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
    $operations = [];

    foreach ($document['paths'] as $pathItem) {
        foreach (['get', 'post', 'put', 'patch', 'delete'] as $method) {
            if (isset($pathItem[$method])) {
                $operations[] = $pathItem[$method];
            }
        }
    }

    $manifest = app(FeatureManifest::class);
    $expectedNames = [];

    foreach ($manifest->definitions() as $definition) {
        foreach ($definition->routeNames as $surface => $names) {
            foreach ($names as $name) {
                $expectedNames[] = "nvl.auth.{$surface}.{$name}";
            }
        }
    }

    $actualNames = array_column($operations, 'operationId');
    sort($expectedNames);
    sort($actualNames);

    expect($actualNames)->toBe($expectedNames);

    foreach ($operations as $operation) {
        $feature = AuthFeature::from($operation['x-nvl-feature']);
        $definition = $manifest->definition($feature);

        expect(FeatureOperation::tryFrom($operation['x-nvl-feature-operation']))->not->toBeNull()
            ->and($operation['x-nvl-route-surface'])->toBeIn(['public', 'account', 'management'])
            ->and($operation['x-nvl-feature-dependencies'])->toBe(array_map(
                static fn (AuthFeature $dependency): string => $dependency->value,
                $definition->dependenciesForSurface($operation['x-nvl-route-surface']),
            ));
    }

    $requestBodyOperations = array_values(array_map(
        static fn (array $operation): string => $operation['operationId'],
        array_filter($operations, static fn (array $operation): bool => isset($operation['requestBody'])),
    ));
    sort($requestBodyOperations);
    $expectedRequestBodyOperations = [
        'nvl.auth.account.api_tokens.rotate',
        'nvl.auth.account.api_tokens.store',
        'nvl.auth.account.api_tokens.update',
        'nvl.auth.account.passkeys.registration.finish',
        'nvl.auth.account.password.confirm',
        'nvl.auth.account.password.update',
        'nvl.auth.account.profile.update',
        'nvl.auth.account.profile.destroy',
        'nvl.auth.account.recovery_codes.consume',
        'nvl.auth.account.totp.confirm',
        'nvl.auth.account.totp.enroll',
        'nvl.auth.account.totp.verify',
        'nvl.auth.management.clients.status',
        'nvl.auth.management.clients.store',
        'nvl.auth.management.clients.update',
        'nvl.auth.management.invitations.store',
        'nvl.auth.management.permissions.store',
        'nvl.auth.management.permissions.update',
        'nvl.auth.management.roles.apply_template',
        'nvl.auth.management.roles.clone',
        'nvl.auth.management.roles.store',
        'nvl.auth.management.roles.update',
        'nvl.auth.management.users.bulk',
        'nvl.auth.management.users.permissions',
        'nvl.auth.management.users.roles',
        'nvl.auth.management.users.status',
        'nvl.auth.management.users.store',
        'nvl.auth.management.users.update',
        'nvl.auth.public.clients.start',
        'nvl.auth.public.invitations.accept',
        'nvl.auth.public.login',
        'nvl.auth.public.magic_links.consume',
        'nvl.auth.public.magic_links.request',
        'nvl.auth.public.passkeys.authentication.finish',
        'nvl.auth.public.password.request',
        'nvl.auth.public.password.reset',
        'nvl.auth.public.security_codes.request',
        'nvl.auth.public.security_codes.verify',
    ];
    sort($expectedRequestBodyOperations);

    expect($requestBodyOperations)->toBe($expectedRequestBodyOperations)
        ->and($document['components']['schemas'])->toHaveKeys([
            'Envelope',
            'LaravelValidationError',
            'Login',
            'PasswordReset',
            'PasskeyFinish',
            'ApiToken',
            'InvitationCreate',
            'ClientMutation',
            'ProfileMutation',
            'AccountDeletion',
            'UserMutation',
            'UserBulk',
            'RoleAssignment',
            'PermissionAssignment',
            'RoleMutation',
            'PermissionMutation',
        ])
        ->and($document['components']['securitySchemes'])->toHaveKeys(['sessionCookie', 'bearerToken'])
        ->and($document['components']['responses']['Success']['headers'])->toHaveKeys([
            'Cache-Control',
            'Referrer-Policy',
        ]);
});
