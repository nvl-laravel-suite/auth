<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Queries\InvitationIndexQueryData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\AuthRequestInput;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account\AuthenticatedController;

/**
 * Handles authorized invitation management transport.
 */
final class InvitationController extends AuthenticatedController
{
    /**
     * List invitations.
     */
    public function index(
        Request $request,
        AuthInvitations $action,
    ): JsonResponse {
        $data = array_replace(['recipient' => null, 'type' => null, 'purpose' => null, 'lifecycle' => null, 'expiresAfter' => null, 'expiresBefore' => null, 'context' => null, 'per_page' => null, 'types' => null], Validator::make(AuthRequestInput::aliased($request->all(), ['expiresAfter' => ['expires_after'], 'expiresBefore' => ['expires_before'], 'per_page' => ['perPage']]), InvitationIndexQueryData::rules())->validate());
        if (isset($data['per_page'])) {
            $data['per_page'] = (int) $data['per_page'];
        }

        $page = $action->paginate($this->subject($request), $data);

        return response()->json(['data' => $page, 'code' => 'invitations_listed', 'message' => trans('nvl-auth::responsecode.invitations_listed')]);
    }

    /**
     * Issue an invitation and emit its delivery event.
     */
    public function store(Request $request, AuthInvitations $action): JsonResponse
    {
        $data = array_replace(['type' => 'registration', 'purpose' => 'registration', 'roles' => [], 'permissions' => [], 'metadata' => [], 'locale' => null, 'context' => null], Validator::make($request->all(), StoreInvitationData::rules())->validate());

        $data['locale'] = $request->getPreferredLanguage();
        $result = $action->create($data, $this->subject($request));

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
