<?php

declare(strict_types=1);

use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\AuthClientSession;
use Nvl\Auth\Services\AuthClients;

beforeEach(function (): void {
    config()->set('nvl-auth.features.clients.enabled', true);
});

it('manages clients and correlates rather than replaces Laravel sessions', function (): void {
    $actor = $this->user('actor@example.test');
    $client = app(AuthClients::class)->create($actor, ['name' => 'Admin Portal', 'surface' => 'web', 'baseUrl' => 'https://admin.example.test', 'returnPaths' => ['/dashboard'], 'allowedOrigins' => ['https://admin.example.test'], 'allowedFlows' => ['login']]);
    $start = app(AuthClients::class)->start(
        ['clientId' => (string) $client->getKey(), 'flow' => 'login', 'returnPath' => '/dashboard', 'origin' => 'https://admin.example.test']
    );
    $session = app(AuthClients::class)->recordSession(
        $client,
        'laravel-session-id',
        $actor,
        '127.0.0.1',
        'Pest',
    );

    expect($start['returnUrl'])->toBe('https://admin.example.test/dashboard')
        ->and(app(AuthClients::class)->find($actor, $client)->is($client))->toBeTrue()
        ->and($session)->toBeInstanceOf(AuthClientSession::class)
        ->and($session->getRawOriginal('session_id_hash'))->not->toBe('laravel-session-id')
        ->and($session->subject_id)->toBe((string) $actor->getKey());

    app(AuthClients::class)->endSession($session);

    expect($session->refresh()->ended_at)->not->toBeNull()
        ->and(AuthAudit::query()->where('action', 'client.started')->exists())->toBeTrue()
        ->and(AuthAudit::query()->where('action', 'client.session_ended')->exists())->toBeTrue();

    expect(fn () => app(AuthClients::class)->recordSession(
        $client,
        'laravel-session-id',
        $actor,
    ))->toThrow(AuthException::class, 'ended');

    $client = app(AuthClients::class)->setActive($actor, $client, false);

    expect($client->is_active)->toBeFalse();
});

it('requires configured origins and rejects correlations for inactive clients', function (): void {
    $actor = $this->user('manager@example.test');
    $client = app(AuthClients::class)->create($actor, ['name' => 'Portal', 'surface' => 'web', 'baseUrl' => 'https://portal.example.test', 'returnPaths' => ['/home'], 'allowedOrigins' => ['https://portal.example.test']]);

    expect(fn () => app(AuthClients::class)->start(
        ['clientId' => $client->identifier(), 'flow' => 'login', 'returnPath' => '/home']
    ))->toThrow(AuthException::class, 'origin');

    app(AuthClients::class)->setActive($actor, $client, false);

    expect(fn () => app(AuthClients::class)->recordSession($client, 'session-id'))
        ->toThrow(AuthException::class, 'unavailable');
});
