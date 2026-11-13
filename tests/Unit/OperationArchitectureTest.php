<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Nvl\Auth\Contracts\AuthenticationAssurancePolicy;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthenticationMethod;
use Nvl\Auth\Services\AuthAuditReader;
use Nvl\Auth\Services\AuthChallenges;
use Nvl\Auth\Services\AuthClients;
use Nvl\Auth\Services\AuthEmailVerification;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthenticationProofs;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Services\AuthMaintenance;
use Nvl\Auth\Services\AuthMemberships;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Services\AuthUserReader;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Services\PrincipalEmailIdentity;
use Nvl\Auth\Services\PrincipalEmailIdentityAdoption;
use Nvl\Auth\Support\SubjectReferences;
use Nvl\Auth\Traits\IssuesAuthenticationProofs;
use Nvl\Auth\ValueObjects\AuthenticationEvidence;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthenticationVerification;
use Nvl\Auth\ValueObjects\IssuedAuthenticationProof;
use Nvl\Auth\ValueObjects\SubjectReference;

it('publishes complete native operations with explicit typed arguments and returns', function (string $class): void {
    $reflection = new ReflectionClass($class);
    expect($reflection->isFinal())->toBeTrue()->and($reflection->isReadOnly())->toBeTrue()
        ->and($reflection->hasMethod('execute'))->toBeFalse();
    foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
        if ($method->isConstructor()) {
            continue;
        }
        expect($method->hasReturnType())->toBeTrue();
        foreach ($method->getParameters() as $parameter) {
            expect($parameter->hasType())->toBeTrue();
            expect((string) $parameter->getType())->not->toContain('Data')->not->toContain('Illuminate\\Http\\Request');
        }
    }
})->with([
    [Authentication::class],
    [AuthenticationSessions::class],
    [AuthChallenges::class],
    [AuthPasswords::class],
    [AuthEmailVerification::class],
    [AuthInvitations::class],
    [AuthUsers::class],
    [AuthUserReader::class],
    [AuthClients::class],
    [AuthMemberships::class],
    [AuthAuditReader::class],
    [AuthMaintenance::class],
]);

it('exposes native operation families without duplicate execute contracts', function (): void {
    foreach (['AuthRegistration', 'Authentication', 'AuthenticationSessions', 'AuthChallenges', 'AuthPasswords', 'AuthEmailVerification', 'AuthInvitations', 'AuthUsers', 'AuthUserReader', 'AuthClients', 'AuthMemberships', 'AuthAuditReader', 'AuthMaintenance', 'AuthTokens', 'AuthRoles', 'AuthPermissions', 'AuthRbacReader', 'AuthSecondFactor', 'AuthPasskeys', 'AuthSocialAuthentication', 'AuthSocialLinks', 'AuthAccountSecurity', 'AuthAccountRecovery', 'AuthEmailChanges', 'AuthBrowserSessions', 'AuthRememberCredentials', 'AuthImpersonation'] as $family) {
        $reflection = new ReflectionClass('Nvl\\Auth\\Services\\'.$family);
        expect($reflection->hasMethod('execute'))->toBeFalse()->and($reflection->getMethods(ReflectionMethod::IS_PUBLIC))->not->toBeEmpty();
    }
    expect(glob(dirname(__DIR__, 2).'/src/Actions/*/*.php'))->toBe([]);
});

it('keeps Actions and Services independent from HTTP transport classes', function (): void {
    foreach (['Services'] as $layer) {
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

it('publishes typed authentication proofs without exposing raw session establishment', function (): void {
    foreach ([
        [Authentication::class, 'verifyCredentials', ['array'], Authenticatable::class],
        [Authentication::class, 'login', ['array', 'array', StatefulGuard::class, Session::class, 'array'], Authenticatable::class],
        [AuthenticationSessions::class, 'establishFromProof', ['string', StatefulGuard::class, Session::class, AuthenticationRequestContext::class, 'bool'], Authenticatable::class],
    ] as [$class, $method, $parameters, $return]) {
        $reflection = new ReflectionMethod($class, $method);
        expect(array_map(static fn (ReflectionParameter $parameter): string => (string) $parameter->getType(), $reflection->getParameters()))->toBe($parameters)
            ->and((string) $reflection->getReturnType())->toBe($return);
    }

    $catalog = json_decode(file_get_contents(__DIR__.'/../../resources/consumer-api.json'), true, flags: JSON_THROW_ON_ERROR)['symbols'];
    foreach ([PrincipalEmailIdentity::class, PrincipalEmailIdentityAdoption::class, Authentication::class, AuthenticationSessions::class, AuthenticationRequestContext::class, AuthenticationProofs::class, AuthenticationAssurancePolicy::class, AuthenticationMethod::class, AuthenticationDestination::class, AuthenticationEvidence::class, IssuedAuthenticationProof::class] as $symbol) {
        expect($catalog)->toHaveKey($symbol);
    }
    expect($catalog[PrincipalEmailIdentity::class]['methods'])->toContain('normalize', 'key')->not->toContain('credentials', 'brokerCredentials', 'assertReady', 'schemaReady', 'indexReady');
    expect($catalog[Authentication::class]['methods'])->toContain('login', 'loginWithToken', 'proveCredentials', 'proveCredentialsForToken')
        ->and($catalog[AuthenticationSessions::class]['methods'])->toContain('establishFromProof')->not->toContain('establish', 'establishForPurpose')
        ->and($catalog[Authentication::class]['methods'])->not->toContain('passwordProof', 'issueNativeProof')
        ->and($catalog[AuthenticationProofs::class]['methods'])->not->toContain('recheck', 'consumeForFinalization')
        ->and($catalog)->not->toHaveKeys([IssuesAuthenticationProofs::class, AuthenticationVerification::class])
        ->and((new ReflectionClass(AuthenticationEvidence::class))->hasProperty('passwordBinding'))->toBeFalse();

    expect(method_exists(AuthenticationSessions::class, 'establish'))->toBeFalse()
        ->and(method_exists(AuthenticationSessions::class, 'establishForPurpose'))->toBeFalse();
});

it('compares subject references strictly without numeric string coercion', function (): void {
    $leadingZeros = new SubjectReference('user', '007');
    $plain = new SubjectReference('user', '7');
    $matching = new SubjectReference('user', '007');

    expect(SubjectReferences::same($leadingZeros, $plain))->toBeFalse()
        ->and(SubjectReferences::same($leadingZeros, $matching))->toBeTrue()
        ->and(SubjectReferences::same($leadingZeros, null))->toBeFalse()
        ->and(SubjectReferences::same(null, null))->toBeTrue();
});
