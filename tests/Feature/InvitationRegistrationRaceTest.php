<?php

declare(strict_types=1);
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Testing\Fakes\EventFake;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Events\InvitationAccepted;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Services\InvitationPrincipalResolver;
use Nvl\Auth\Services\PackageInvitationSubjectResolver;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\Tests\Fixtures\SecurityRace;
use Nvl\Auth\Tests\Fixtures\TestUser;

beforeEach(function (): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'invitation_only']);
});

it('never returns a principal inserted after invitation signup checked the mailbox', function (): void {
    $existing = $this->user('invitee@example.test');
    $invitation = Invitation::factory()->create(['recipient' => $existing->email]);
    expect(fn () => app(PackageInvitationSubjectResolver::class)->resolve($invitation, [
        'name' => 'Attacker', 'password' => 'new-password-123', 'password_confirmation' => 'new-password-123',
    ]))->toThrow(UniqueConstraintViolationException::class);
    expect(TestUser::query()->where('email', $existing->email)->count())->toBe(1)->and($existing->refresh()->name)->toBe('Test User');
});

it('rejects a competing committed mailbox insert during invitation registration', function (): void {
    config(['nvl-auth.features.invitations.enabled' => true]);
    $token = 'invitation-race-token';
    $invitation = Invitation::factory()->create(['recipient' => 'race@example.test', 'token_hash' => app(SecretHasher::class)->hash('invitation-token', $token)]);
    $gate = tempnam(sys_get_temp_dir(), 'invitation-insert-race-');
    try {
        $signup = static function () use ($gate, $token): array {
            app()->bind(InvitationSubjectResolver::class, static fn () => new class($gate) implements InvitationSubjectResolver
            {
                public function __construct(private string $gate) {}

                public function resolve(Invitation $invitation, #[SensitiveParameter] array $input): Authenticatable
                {
                    file_put_contents($this->gate, 'lookup-completed');
                    SecurityRace::wait(fn (): bool => file_get_contents($this->gate) === 'insert-committed');

                    return app(PackageInvitationSubjectResolver::class)->resolve($invitation, $input);
                }
            });
            try {
                app(AuthInvitations::class)->register(['token' => $token, 'name' => 'Signup', 'password' => 'new-password-123', 'passwordConfirmation' => 'new-password-123']);

                return ['accepted' => true];
            } catch (AuthException $exception) {
                return ['accepted' => false, 'rejection' => $exception->errorCode];
            }
        };
        $insert = static function () use ($gate): array {
            SecurityRace::wait(fn (): bool => file_get_contents($gate) === 'lookup-completed');
            TestUser::query()->create(['email' => 'race@example.test', 'name' => 'Existing owner', 'password' => 'existing-password']);
            file_put_contents($gate, 'insert-committed');

            return [];
        };
        $results = SecurityRace::run([$signup, $insert]);
        expect(array_column($results, 'ok'))->toBe([true, true], json_encode($results, JSON_THROW_ON_ERROR))
            ->and($results[0]['accepted'])->toBeFalse()
            ->and($results[0]['rejection'])->toBe('invitation_principal_conflict')
            ->and($invitation->refresh()->accepted_at)->toBeNull()
            ->and(TestUser::query()->where('email', 'race@example.test')->sole()->name)->toBe('Existing owner');
    } finally {
        unlink($gate);
    }
})->skip(fn (): bool => DB::connection()->getDriverName() === 'sqlite', 'Committed process race requires PostgreSQL.');

it('rejects a cached recently-created principal returned without an in-operation creation receipt', function (): void {
    config(['nvl-auth.features.invitations.enabled' => true]);
    $cached = $this->user('before@example.test');
    expect($cached->wasRecentlyCreated)->toBeTrue();
    $token = 'cached-recipient-token';
    Invitation::factory()->create(['recipient' => 'after@example.test', 'token_hash' => app(SecretHasher::class)->hash('invitation-token', $token)]);
    app()->instance(InvitationSubjectResolver::class, new class($cached) implements InvitationSubjectResolver
    {
        public function __construct(private TestUser $user) {}

        public function resolve(Invitation $invitation, #[SensitiveParameter] array $input): Authenticatable
        {
            $this->user->update(['email' => $invitation->recipient]);

            return $this->user;
        }
    });
    $dispatcher = TestUser::getEventDispatcher();
    expect(fn () => app(AuthInvitations::class)->register(['token' => $token, 'name' => 'Signup', 'password' => 'new-password-123', 'passwordConfirmation' => 'new-password-123']))
        ->toThrow(AuthException::class, 'recipient identity');
    expect(TestUser::getEventDispatcher())->toBe($dispatcher)
        ->and($cached->refresh()->email)->toBe('before@example.test');
});

it('restores the exact dispatcher after a resolver exception', function (): void {
    $invitation = Invitation::factory()->create();
    $dispatcher = TestUser::getEventDispatcher();
    app()->instance(InvitationSubjectResolver::class, new class implements InvitationSubjectResolver
    {
        public function resolve(Invitation $invitation, #[SensitiveParameter] array $input): Authenticatable
        {
            throw new RuntimeException('resolver failed');
        }
    });
    expect(fn () => DB::transaction(fn () => app(InvitationPrincipalResolver::class)->resolve($invitation, [], null)))->toThrow(RuntimeException::class, 'resolver failed');
    expect(TestUser::getEventDispatcher())->toBe($dispatcher);
});

it('preserves consumer created observers during nested invitation resolution', function (): void {
    $outer = Invitation::factory()->create(['recipient' => 'outer@example.test']);
    $inner = Invitation::factory()->create(['recipient' => 'inner@example.test']);
    $original = TestUser::getEventDispatcher();
    $dispatcher = clone $original;
    $observed = [];
    $dispatcher->listen('eloquent.created: '.TestUser::class, function (TestUser $user) use (&$observed): void {
        $observed[] = $user->email;
    });
    TestUser::setEventDispatcher($dispatcher);
    try {
        app()->instance(InvitationSubjectResolver::class, new class($inner) implements InvitationSubjectResolver
        {
            private bool $nested = false;

            public function __construct(private Invitation $inner) {}

            public function resolve(Invitation $invitation, #[SensitiveParameter] array $input): Authenticatable
            {
                if (! $this->nested) {
                    $this->nested = true;
                    app(InvitationPrincipalResolver::class)->resolve($this->inner, $input, null);
                }

                return app(PackageInvitationSubjectResolver::class)->resolve($invitation, $input);
            }
        });
        $input = ['name' => 'Nested', 'password' => 'new-password-123'];
        DB::transaction(fn () => app(InvitationPrincipalResolver::class)->resolve($outer, $input, null));
        expect($observed)->toBe(['inner@example.test', 'outer@example.test'])
            ->and(TestUser::getEventDispatcher())->toBe($dispatcher);
    } finally {
        TestUser::setEventDispatcher($original);
    }
});

it('leaves forwarding dispatcher listener registries unchanged after resolver success or failure', function (bool $fail): void {
    $invitation = Invitation::factory()->create();
    $original = TestUser::getEventDispatcher();
    new TestUser;
    $listeners = $original->getRawListeners();
    $forwarding = new EventFake($original, [InvitationAccepted::class]);
    TestUser::setEventDispatcher($forwarding);
    try {
        if ($fail) {
            app()->instance(InvitationSubjectResolver::class, new class implements InvitationSubjectResolver
            {
                public function resolve(Invitation $invitation, #[SensitiveParameter] array $input): Authenticatable
                {
                    throw new RuntimeException('forwarded resolver failed');
                }
            });
            expect(fn () => DB::transaction(fn () => app(InvitationPrincipalResolver::class)->resolve($invitation, [], null)))->toThrow(RuntimeException::class, 'forwarded resolver failed');
        } else {
            DB::transaction(fn () => app(InvitationPrincipalResolver::class)->resolve($invitation, ['name' => 'Forwarded', 'password' => 'new-password-123'], null));
        }
        expect(TestUser::getEventDispatcher())->toBe($forwarding)
            ->and($original->getRawListeners())->toBe($listeners);
    } finally {
        TestUser::setEventDispatcher($original);
    }
})->with([false, true]);
