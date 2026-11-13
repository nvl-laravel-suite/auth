<?php

declare(strict_types=1);

use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\PrincipalSecurityState;
use Nvl\Auth\Services\AuthMaintenance;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Services\AuthReauthentication;
use Nvl\Auth\Services\AuthUserReader;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Services\PrincipalSecurity;
use Nvl\Auth\Tests\Fixtures\AuthOwnerScenario;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;

it('prunes bounded terminal invitations only from the admitted owner source', function (): void {
    $this->withFixtureConfiguration(['nvl-auth.cleanup.batch_size' => 2], function (): void {
        $scenario = new AuthOwnerScenario;
        foreach ([[$scenario->a(), 3], [$scenario->b(), 2]] as [$owner, $count]) {
            $scenario->run($owner, fn () => Invitation::factory()->count($count)->create(['expires_at' => now()->subDays(40)]));
        }
        $counts = $scenario->run($scenario->a(), fn () => app(AuthMaintenance::class)->prune(new SystemMutationContext('Owned retention', 'prune-owner')));

        expect($counts['invitations'])->toBe(3)
            ->and($scenario->run($scenario->a(), fn () => Invitation::query()->count()))->toBe(0)
            ->and($scenario->run($scenario->b(), fn () => Invitation::query()->count()))->toBe(2);
    });
});

it('does not let a tenant owner delete or enumerate a global principal', function (): void {
    $scenario = new AuthOwnerScenario;
    $owner = $this->user('owner-boundary@example.test');
    $target = $this->user('target-boundary@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($owner), true);

    expect(fn () => $scenario->run($scenario->a(), fn () => app(AuthUsers::class)->delete($owner, $target)))
        ->toThrow(OwnershipViolation::class)
        ->and(fn () => $scenario->run($scenario->a(), fn () => app(AuthUserReader::class)->find($owner, $target)))
        ->toThrow(OwnershipViolation::class);
    expect($target->fresh())->not->toBeNull();
});

it('permits global principal administration only in explicit platform context', function (): void {
    $scenario = new AuthOwnerScenario;
    $actor = $this->user('platform-admin@example.test');
    $target = $this->user('platform-target@example.test');

    $deleted = $scenario->platform(fn () => app(AuthUsers::class)->delete($actor, $target));

    expect($deleted)->toBeTrue()->and(TestUser::query()->find($target->id))->toBeNull();
});

it('contains package tokens in every owner while preserving unrelated namespaces', function (): void {
    $scenario = new AuthOwnerScenario;
    $user = $this->user('global-credential@example.test');
    expect(app(PrincipalSecurity::class)->revision($user))->toBe(1);
    expect($scenario->run($scenario->a(), fn () => app(PrincipalSecurity::class)->revision($user)))->toBe(1);
    $tokens = [];
    foreach ([$scenario->a(), $scenario->b()] as $owner) {
        $tokens[] = $scenario->run($owner, fn () => $user->createToken('nvl-auth:managed')->accessToken);
        $unrelated = $scenario->run($owner, fn () => $user->createToken('consumer:unrelated')->accessToken);
    }
    $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: app('session.store')->getId());
    $grant = $scenario->platform(fn () => app(AuthReauthentication::class)->confirm($user, ['password' => 'correct-password'], RecentAuthenticationPurpose::PasswordChange, $context));
    $scenario->platform(fn () => app(AuthPasswords::class)->update($user, ['password' => 'new-password-123', 'passwordConfirmation' => 'new-password-123'], $grant->reveal(), $context));
    $table = $tokens[0]->getTable();
    expect($user->getConnection()->table($table)->whereIn('id', array_map(fn ($token) => $token->getKey(), $tokens))->count())->toBe(0)
        ->and($user->getConnection()->table($table)->where('id', $unrelated->getKey())->exists())->toBeTrue();
    $state = PrincipalSecurityState::query()->sole();
    expect($state->revision)->toBe(2)->and($state->getAttribute('owner_scope_key'))->toBeNull();
});
