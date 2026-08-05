<?php

declare(strict_types=1);

use Nvl\Auth\Actions\Clients\CreateAuthClientAction;
use Nvl\Auth\Actions\Clients\EndAuthClientSessionAction;
use Nvl\Auth\Actions\Clients\RecordAuthClientSessionAction;
use Nvl\Auth\Actions\Clients\SetAuthClientActiveAction;
use Nvl\Auth\Actions\Clients\ShowAuthClientAction;
use Nvl\Auth\Actions\Clients\StartAuthClientAction;
use Nvl\Auth\Data\Mutations\StartClientAuthData;
use Nvl\Auth\Data\Mutations\StoreClientData;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\AuthClientSession;

beforeEach(function (): void {
    config()->set('nvl-auth.features.clients.enabled', true);
});

it('manages clients and correlates rather than replaces Laravel sessions', function (): void {
    $actor = $this->user('actor@example.test');
    $client = app(CreateAuthClientAction::class)->execute($actor, new StoreClientData(
        name: 'Admin Portal',
        surface: 'web',
        baseUrl: 'https://admin.example.test',
        returnPaths: ['/dashboard'],
        allowedOrigins: ['https://admin.example.test'],
        allowedFlows: ['login'],
    ));
    $start = app(StartAuthClientAction::class)->execute(
        new StartClientAuthData(
            (string) $client->getKey(),
            'login',
            '/dashboard',
            'https://admin.example.test',
        )
    );
    $session = app(RecordAuthClientSessionAction::class)->execute(
        $client,
        'laravel-session-id',
        $actor,
        '127.0.0.1',
        'Pest',
    );

    expect($start->returnUrl)->toBe('https://admin.example.test/dashboard')
        ->and(app(ShowAuthClientAction::class)->execute($actor, $client)->is($client))->toBeTrue()
        ->and($session)->toBeInstanceOf(AuthClientSession::class)
        ->and($session->getRawOriginal('session_id_hash'))->not->toBe('laravel-session-id')
        ->and($session->subject_id)->toBe((string) $actor->getKey());

    app(EndAuthClientSessionAction::class)->execute($session);

    expect($session->refresh()->ended_at)->not->toBeNull()
        ->and(AuthAudit::query()->where('action', 'client.started')->exists())->toBeTrue()
        ->and(AuthAudit::query()->where('action', 'client.session_ended')->exists())->toBeTrue();

    expect(fn () => app(RecordAuthClientSessionAction::class)->execute(
        $client,
        'laravel-session-id',
        $actor,
    ))->toThrow(AuthException::class, 'ended');

    $client = app(SetAuthClientActiveAction::class)->execute($actor, $client, false);

    expect($client->is_active)->toBeFalse();
});

it('requires configured origins and rejects correlations for inactive clients', function (): void {
    $actor = $this->user('manager@example.test');
    $client = app(CreateAuthClientAction::class)->execute($actor, new StoreClientData(
        name: 'Portal',
        surface: 'web',
        baseUrl: 'https://portal.example.test',
        returnPaths: ['/home'],
        allowedOrigins: ['https://portal.example.test'],
    ));

    expect(fn () => app(StartAuthClientAction::class)->execute(
        new StartClientAuthData(
            $client->identifier(),
            'login',
            '/home',
        )
    ))->toThrow(AuthException::class, 'origin');

    app(SetAuthClientActiveAction::class)->execute($actor, $client, false);

    expect(fn () => app(RecordAuthClientSessionAction::class)->execute($client, 'session-id'))
        ->toThrow(AuthException::class, 'unavailable');
});
