<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\ListApiTokensContract;
use Nvl\Auth\Contracts\ListInvitationProjectionsContract;
use Nvl\Auth\Contracts\LogoutContract;
use Nvl\Auth\Data\Display\InvitationReadData;
use Nvl\Auth\ValueObjects\ApiTokenSnapshot;

/** A real host service which turns package results into its own presentation. */
final readonly class AuthConsumerWorkflow
{
    public function __construct(private ListApiTokensContract $tokens, private ListInvitationProjectionsContract $invitations, private LogoutContract $logout) {}

    /** @return list<string> */
    public function tokenNames(Authenticatable $actor): array
    {
        return array_map(static fn (ApiTokenSnapshot $token): string => $token->name, $this->tokens->execute($actor));
    }

    /** @return list<string> */
    public function invitationRecipients(Authenticatable $actor): array
    {
        return array_map(static fn (InvitationReadData $invitation): string => $invitation->recipient, $this->invitations->execute($actor, null, 10)->items());
    }

    /** Continue host orchestration after the void package boundary. */
    public function signOut(): string
    {
        $this->logout->execute();

        return '/signed-out';
    }
}
