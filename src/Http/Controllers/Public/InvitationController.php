<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Nvl\Auth\Actions\Invitations\AcceptInvitationAction;
use Nvl\Auth\Actions\Invitations\PreviewInvitationAction;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Data\Mutations\AcceptInvitationData;
use Nvl\Auth\Http\Controllers\Concerns\InteractsWithValidatedInput;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Handles public invitation acceptance through a host subject resolver.
 */
final class InvitationController
{
    use InteractsWithValidatedInput;

    /**
     * Provision or resolve the host subject and consume the invitation.
     */
    public function accept(
        AcceptInvitationData $data,
        PreviewInvitationAction $preview,
        InvitationSubjectResolver $subjects,
        AcceptInvitationAction $accept,
    ): JsonResponse {
        $token = $data->token;
        $invitation = $preview->execute($token);
        $subject = $subjects->resolve($invitation, $data->toRegistrationArray());
        $accepted = $accept->execute($token, $subject);
        $reference = SubjectReference::fromAuthenticatable($subject);

        return response()->json([
            'data' => [
                'invitation_id' => $accepted->identifier(),
                'subject' => ['type' => $reference->type, 'id' => $reference->identifier],
            ],
            'code' => 'invitation_accepted',
            'message' => 'The invitation was accepted.',
        ]);
    }
}
