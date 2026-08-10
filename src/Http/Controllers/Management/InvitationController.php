<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Invitations\CreateInvitationAction;
use Nvl\Auth\Actions\Invitations\ListInvitationsAction;
use Nvl\Auth\Actions\Invitations\ResendInvitationAction;
use Nvl\Auth\Actions\Invitations\RevokeInvitationAction;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Data\Queries\InvitationIndexQueryData;
use Nvl\Auth\Http\Controllers\Account\AuthenticatedController;
use Nvl\Auth\Models\Invitation;

/**
 * Handles authorized invitation management transport.
 */
final class InvitationController extends AuthenticatedController
{
    /**
     * List invitations.
     */
    public function index(
        InvitationIndexQueryData $data,
        Request $request,
        ListInvitationsAction $action,
    ): JsonResponse {
        $page = $action->execute($this->subject($request), $data);

        return response()->json(['data' => $page, 'code' => 'invitations_listed', 'message' => 'Invitations were listed.']);
    }

    /**
     * Issue an invitation and emit its delivery event.
     */
    public function store(StoreInvitationData $data, Request $request, CreateInvitationAction $action): JsonResponse
    {
        $data->locale = $request->getPreferredLanguage();
        $result = $action->execute($data, $this->subject($request));

        return response()->json([
            'data' => ['invitation_id' => $result->invitation->identifier(), 'expires_at' => $result->invitation->expires_at->toIso8601String()],
            'code' => 'invitation_issued',
            'message' => 'The invitation was issued.',
        ], 201);
    }

    /**
     * Rotate and resend an invitation token.
     */
    public function resend(
        Request $request,
        Invitation $invitation,
        ResendInvitationAction $action,
    ): JsonResponse {
        $action->execute($invitation, $this->subject($request), $request->getPreferredLanguage());

        return response()->json(['data' => null, 'code' => 'invitation_resent', 'message' => 'The invitation was resent.']);
    }

    /**
     * Revoke an invitation.
     */
    public function destroy(
        Request $request,
        Invitation $invitation,
        RevokeInvitationAction $action,
    ): JsonResponse {
        $action->execute($invitation, $this->subject($request));

        return response()->json(['data' => null, 'code' => 'invitation_revoked', 'message' => 'The invitation was revoked.']);
    }
}
