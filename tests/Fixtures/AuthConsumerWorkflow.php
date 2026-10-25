<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Services\AuthTokens;

/** A real host service which turns package results into its own presentation. */
final readonly class AuthConsumerWorkflow
{
    public function __construct(private AuthTokens $tokens, private AuthInvitations $invitations, private AuthenticationSessions $sessions) {}

    /** @return list<string> */
    public function tokenNames(Authenticatable $actor): array
    {
        return array_map(static fn (array $token): string => $token['name'], $this->tokens->all($actor));
    }

    /** @return list<string> */
    public function invitationRecipients(Authenticatable $actor): array
    {
        return array_map(static fn (Invitation $invitation): string => $invitation->recipient, $this->invitations->paginate($actor, [], 10)->items());
    }

    /** Continue host orchestration after the void package boundary. */
    public function signOut(StatefulGuard $guard, Session $session): string
    {
        $this->sessions->logout($guard, $session);

        return '/signed-out';
    }
}
