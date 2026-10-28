<?php

declare(strict_types=1);

use Nvl\Auth\Contracts\AuthPipelineStage;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Services\AuthRegistration;
use Nvl\Auth\ValueObjects\AuthPipelineContext;

function lifecycleStage(string $pipeline, Closure $callback): void
{
    $stage = new LifecycleTestStage($callback);
    app()->instance($stage::class, $stage);
    config()->set('nvl-auth.pipelines.'.$pipeline, [$stage::class]);
}

final class LifecycleTestStage implements AuthPipelineStage
{
    public function __construct(private Closure $callback) {}

    public function handle(AuthPipelineContext $context, Closure $next): mixed
    {
        return ($this->callback)($context, $next);
    }
}

it('rejects substituted and in-place changed terminal model identities', function (string $mutation): void {
    $user = $this->user();
    $other = $this->user('other@example.test');
    lifecycleStage('login', function ($context, $next) use ($mutation, $other) {
        $result = $next($context);
        if ($mutation === 'replace') {
            return $other;
        }
        if ($mutation === 'key') {
            $result->setAttribute($result->getKeyName(), $other->getKey());
        }
        if ($mutation === 'connection') {
            $result->setConnection('forged');
        }

        return $result;
    });
    expect(fn () => app(AuthPipeline::class)->run('login', new AuthPipelineContext('login'), fn () => $user))
        ->toThrow(AuthException::class);
})->with(['replace', 'key', 'connection']);

it('rolls back native signup when an after-terminal registration hook denies it', function (): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open']);
    lifecycleStage('registration', function ($context, $next) {
        $next($context);
        throw new AuthException('registration_denied', 'Hook rejected signup.');
    });
    expect(fn () => app(AuthRegistration::class)->register(['name' => 'Rejected', 'email' => 'rejected@example.test', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123']))
        ->toThrow(AuthException::class, 'Hook rejected');
    expect(User::query()->count())->toBe(0);
});

it('requires exactly one native terminal and exposes only signup field names', function (string $behavior): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open']);
    lifecycleStage('registration', function ($context, $next) use ($behavior) {
        expect($context->attributes)->toBe(['method' => 'password', 'attributes' => ['name', 'email', 'password', 'locale', 'timezone', 'extensions']]);
        if ($behavior === 'skip') {
            return null;
        }
        $result = $next($context);
        $next($context);

        return $result;
    });
    expect(fn () => app(AuthRegistration::class)->register(['name' => 'Rejected', 'email' => 'rejected@example.test', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123']))->toThrow(AuthException::class);
    expect(User::query()->count())->toBe(0);
})->with(['skip', 'double']);

it('protects model identity inside native result arrays', function (): void {
    $user = $this->user();
    $other = $this->user('nested@example.test');
    lifecycleStage('login', function ($context, $next) use ($other) {
        $result = $next($context);
        $result['subject']->setAttribute($result['subject']->getKeyName(), $other->getKey());

        return $result;
    });
    expect(fn () => app(AuthPipeline::class)->run('login', new AuthPipelineContext('login'), fn () => ['subject' => $user]))->toThrow(AuthException::class);
});
