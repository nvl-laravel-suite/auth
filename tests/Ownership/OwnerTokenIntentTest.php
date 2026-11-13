<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Nvl\Auth\Enums\OwnerAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\PersonalAccessToken;
use Nvl\Auth\Models\User;
use Nvl\Auth\Results\IssuedApiToken;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthMemberships;
use Nvl\Auth\Services\AuthOwnerAdmission;
use Nvl\Auth\Services\AuthTokens;
use Nvl\Auth\Services\OwnerAuthenticationIntents;
use Nvl\Auth\Tests\OwnerScopeTestCase;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Ownership\Services\OwnerIdentityResolver;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Ownership\Tests\Fixtures\OptsIntoAdoptedSchemaReuse;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\Enums\OwnershipContextMode;

uses(OwnerScopeTestCase::class, OptsIntoAdoptedSchemaReuse::class);

it('binds real Sanctum tokens to the complete owner despite membership in both owners', function (): void {
    config(['nvl-auth.features.api_tokens.enabled' => true, 'nvl-auth.features.api_tokens.settings.abilities' => ['profile:read']]);
    $user = User::factory()->create();
    $actor = Actor::query()->findOrFail(1);
    $runner = app(OwnershipRunner::class);
    $company = Company::query()->findOrFail(7);
    $token = $runner->run($company, $actor, function () use ($user): IssuedApiToken {
        app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'b7'), SubjectReference::fromAuthenticatable($user));

        return app(AuthTokens::class)->create($user, ['name' => 'browser', 'abilities' => ['profile:read']]);
    });
    $runner->run(Company::query()->findOrFail(8), $actor, function () use ($user, $token): void {
        app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'b8'), SubjectReference::fromAuthenticatable($user));
        expect(app(AuthTokens::class)->all($user))->toBe([]);
        $stored = (new PersonalAccessToken)->getConnection()->table('nvl_auth_personal_access_tokens')->where('id', $token->token['id'])->first();
        $foreign = (new PersonalAccessToken)->newFromBuilder((array) $stored);
        $user->withAccessToken($foreign);
        expect(fn () => app(AuthOwnerAdmission::class)->assertAllowed($user))->toThrow(AuthException::class);
    });
});

it('consumes an owner selection intent once and only for its browser owner and purpose', function (): void {
    $owner = app(OwnerIdentityResolver::class)->reference(Company::query()->findOrFail(7));
    $foreign = app(OwnerIdentityResolver::class)->reference(Company::query()->findOrFail(8));
    $intents = app(OwnerAuthenticationIntents::class);
    $issued = $intents->issue($owner, OwnerAuthenticationPurpose::Login, 'browser-session');
    foreach ([[$foreign, OwnerAuthenticationPurpose::Login, 'browser-session'], [$owner, OwnerAuthenticationPurpose::MagicLink, 'browser-session'], [$owner, OwnerAuthenticationPurpose::Login, 'foreign-browser']] as [$expected, $purpose, $binding]) {
        expect(fn () => $intents->consume($issued['nonce'], $purpose, $binding, $expected))->toThrow(AuthException::class);
    }
    expect($intents->consume($issued['nonce'], OwnerAuthenticationPurpose::Login, 'browser-session', $owner))->toEqual($owner)
        ->and(fn () => $intents->consume($issued['nonce'], OwnerAuthenticationPurpose::Login, 'browser-session', $owner))->toThrow(AuthException::class);
});

it('keeps successful global login separate from one-use owner selection', function (): void {
    $user = User::factory()->create();
    $company = Company::query()->findOrFail(7);
    app(OwnershipRunner::class)->run($company, Actor::query()->findOrFail(1), fn () => app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'login'), SubjectReference::fromAuthenticatable($user)));
    $reference = app(OwnerIdentityResolver::class)->reference($company);
    $proof = app(OwnerAuthenticationIntents::class)->issue($reference, OwnerAuthenticationPurpose::Login, 'login-browser');
    $session = app('session')->driver();
    $session->start();
    $previousSessionId = $session->getId();
    $context = ['ownerIntentNonce' => $proof['nonce'], 'ownerSessionBinding' => 'login-browser', 'requestedOwner' => $reference];
    foreach ([1, 2] as $attempt) {
        $result = app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'password'], $context, auth()->guard('web'), app('session')->driver());
        expect($result->getAuthIdentifier())->toBe($user->id)->and($session->getId())->not->toBe($previousSessionId);
        $previousSessionId = $session->getId();
    }
    expect(app(OwnershipContext::class)->snapshot()->mode)->toBe(OwnershipContextMode::Unresolved);
    $audits = (new AuthAudit)->getConnection()->table('nvl_auth_audits');
    expect((clone $audits)->where('action', 'authentication.owner_selected')->count())->toBe(1)
        ->and((clone $audits)->where('action', 'authentication.owner_selection_denied')->count())->toBe(1);
});

it('rejects relabeling a persisted native token principal at the database boundary', function (): void {
    $user = User::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($user): void {
        app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'token-identity'), SubjectReference::fromAuthenticatable($user));
        $issued = app(AuthTokens::class)->create($user, ['name' => 'identity', 'abilities' => ['profile:read']]);
        expect(fn () => (new PersonalAccessToken)->getConnection()->table('nvl_auth_personal_access_tokens')->where('id', $issued->token['id'])->update(['tokenable_id' => 'foreign-principal']))
            ->toThrow(QueryException::class);
    });
});
