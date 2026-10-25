<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Queries\InvitationIndexQueryData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account\AuthenticatedController;
use Spatie\LaravelData\Optional;

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
        AuthInvitations $action,
    ): JsonResponse {
        $page = $action->paginate($this->subject($request), array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional));

        return response()->json(['data' => $page, 'code' => 'invitations_listed', 'message' => trans('nvl-auth::responsecode.invitations_listed')]);
    }

    /**
     * Issue an invitation and emit its delivery event.
     */
    public function store(StoreInvitationData $data, Request $request, AuthInvitations $action): JsonResponse
    {
        $data->locale = $request->getPreferredLanguage();
        $result = $action->create(array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional), $this->subject($request));

        return response()->json([
            'data' => ['invitation_id' => $result['invitation']->identifier(), 'expires_at' => $result['invitation']->expires_at->toIso8601String()],
            'code' => 'invitation_issued', 'message' => trans('nvl-auth::responsecode.invitation_issued'),
        ], 201);
    }

    /**
     * Rotate and resend an invitation token.
     */
    public function resend(
        Request $request,
        Invitation $invitation,
        AuthInvitations $action,
    ): JsonResponse {
        $action->resend($invitation, $this->subject($request), $request->getPreferredLanguage());

        return response()->json(['data' => null, 'code' => 'invitation_resent', 'message' => trans('nvl-auth::responsecode.invitation_resent')]);
    }

    /**
     * Revoke an invitation.
     */
    public function destroy(
        Request $request,
        Invitation $invitation,
        AuthInvitations $action,
    ): JsonResponse {
        $action->revoke($invitation, $this->subject($request));

        return response()->json(['data' => null, 'code' => 'invitation_revoked', 'message' => trans('nvl-auth::responsecode.invitation_revoked')]);
    }
}
