<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Nvl\Auth\Contracts\InvitationRecipientProof;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\ValueObjects\SubjectReference;

/** Requires a canonical principal with a verified address matching the invitation. */
final readonly class VerifiedInvitationRecipientProof implements InvitationRecipientProof
{
    public function __construct(private MembershipPrincipalResolver $principals) {}

    public function assertMatches(Invitation $invitation, Authenticatable $subject): void
    {
        $principal = $this->principals->resolve(SubjectReference::fromAuthenticatable($subject));
        if (! $principal instanceof MustVerifyEmail
            || ! $principal->hasVerifiedEmail()
            || ! hash_equals(
                mb_strtolower(trim($invitation->recipient)),
                mb_strtolower(trim($principal->getEmailForVerification())),
            )) {
            throw new AuthException(
                'invitation_identity_proof_required',
                'The invitation recipient identity could not be verified.',
                403,
            );
        }
    }
}
