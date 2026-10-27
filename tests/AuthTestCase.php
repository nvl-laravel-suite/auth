<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Sanctum\SanctumServiceProvider;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthReauthentication;
use Nvl\Auth\Services\AuthSocialIdentities;
use Nvl\Auth\Tests\Fixtures\AllowAllManagementAccess;
use Nvl\Auth\Tests\Fixtures\AllowAllSystemMutationAccess;
use Nvl\Auth\Tests\Fixtures\Consumer\RouteServiceProvider;
use Nvl\Auth\Tests\Fixtures\TestSubjectResolver;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\IssuedRecentAuthentication;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Providers\LocaleServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;
use PragmaRX\Google2FA\Google2FA;
use Spatie\LaravelData\LaravelDataServiceProvider;
use Spatie\Permission\PermissionRegistrar;
use Spatie\Permission\PermissionServiceProvider;

/**
 * Boots NVL Auth with only its declared integration providers.
 */
abstract class AuthTestCase extends Orchestra
{
    /**
     * Register package integration providers.
     *
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            LocaleServiceProvider::class,
            PermissionServiceProvider::class,
            SanctumServiceProvider::class,
            LaravelDataServiceProvider::class,
            AuthServiceProvider::class,
            RouteServiceProvider::class,
        ];
    }

    /**
     * Configure the isolated host application.
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.name', 'NVL Auth Test');
        $app['config']->set('app.url', 'https://auth-package.test');
        $app['config']->set('app.key', 'base64:YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=');
        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.defaults.passwords', 'users');
        $app['config']->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $app['config']->set('auth.providers.users', ['driver' => 'eloquent', 'model' => TestUser::class]);
        $app['config']->set('auth.passwords.users', ['provider' => 'users', 'table' => 'nvl_auth_password_reset_tokens', 'expire' => 60, 'throttle' => 0]);
        $app['config']->set('nvl-auth.features.principal_management.models.user', TestUser::class);

        $app['config']->set('nvl-auth.migrations.install_all', true);
        $app['config']->set('nvl-auth.features.api_tokens.enabled', true);
        $app['config']->set('nvl-auth.features.api_tokens.settings.abilities', ['profile:read']);
        $app['config']->set('nvl-auth.routes', (require __DIR__.'/Fixtures/Consumer/config.php')['routes']);
        $app['config']->set('nvl-auth.routes.enabled', false);
        $app['config']->set('nvl-auth.routes.public.enabled', false);
        $app['config']->set('nvl-auth.routes.account.enabled', false);
        $app['config']->set('nvl-auth.routes.management.enabled', false);
    }

    /**
     * Bind permissive host contracts for use-case tests.
     */
    protected function setUp(): void
    {
        parent::setUp();
        config([
            'nvl-auth.adoption.principal_model' => ['enabled' => true, 'guard' => 'web', 'provider' => 'users'],
            'nvl-auth.adoption.password_broker' => ['enabled' => true, 'broker' => 'users'],
            'nvl-auth.adoption.spatie_storage.enabled' => true,
        ]);
        (new AuthServiceProvider($this->app))->boot($this->app->make(AuthConfiguration::class));
        $this->app->make(PermissionRegistrar::class);

        $this->app->singleton(AuthManagementAccess::class, AllowAllManagementAccess::class);
        $this->app->singleton(AuthSubjectResolver::class, TestSubjectResolver::class);
        $this->app->singleton(SystemMutationAccess::class, AllowAllSystemMutationAccess::class);
    }

    /** Trusted browser binding for direct native service tests. */
    protected function authenticationContext(): AuthenticationRequestContext
    {
        return new AuthenticationRequestContext(guardName: 'web', sessionBinding: app('session.store')->getId());
    }

    /** Obtain real native authority for lifecycle fixtures; advance only a spent TOTP timestep. */
    protected function recentGrant(Authenticatable $subject, RecentAuthenticationPurpose $purpose, string $password = 'correct-password'): IssuedRecentAuthentication
    {
        $proof = ['password' => $password];
        $reference = SubjectReference::fromAuthenticatable($subject);
        $credential = TotpCredential::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNotNull('confirmed_at')->whereNull('revoked_at')->first();
        if ($credential !== null) {
            $next = ($credential->last_accepted_timestep ?? 0) * $credential->period + $credential->period;
            if ($next > now()->timestamp) {
                $this->travelTo(CarbonImmutable::createFromTimestampUTC($next));
            }
            $totp = new Google2FA;
            $totp->setEnforceGoogleAuthenticatorCompatibility(false);
            $totp->setAlgorithm($credential->algorithm);
            $totp->setOneTimePasswordLength($credential->digits);
            $proof['code'] = $totp->oathTotp($credential->secret, intdiv(now()->timestamp, $credential->period));
        }

        return app(AuthReauthentication::class)->confirm($subject, $proof, $purpose, $this->authenticationContext());
    }

    /** Complete the real native provider intent when a test exercises social login. */
    protected function completeSocialAuthentication(AuthSocialIdentities $service, string $provider): SocialIdentity
    {
        $context = $this->authenticationContext();
        $started = $service->startAuthentication($provider, $context);
        $service->finishAuthentication($provider, $started['intent']->reveal(), $context);

        return SocialIdentity::query()->where('provider', $provider)->firstOrFail();
    }

    /**
     * Create one conventional fixture user.
     */
    protected function user(string $email = 'user@example.test'): TestUser
    {
        return TestUser::query()->create([
            'name' => 'Test User',
            'email' => $email,
            'password' => 'correct-password',
        ]);
    }
}
