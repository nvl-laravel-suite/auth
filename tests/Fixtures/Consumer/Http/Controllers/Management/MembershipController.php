<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthMemberships;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\EnrollMembershipInputData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\MembershipRevisionData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\TransferMembershipOwnershipData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\UpdateMembershipStatusData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Queries\MembershipIndexQueryData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\AuthRequestInput;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account\AuthenticatedController;

/** Handles tenant membership management transport. */
final class MembershipController extends AuthenticatedController
{
    public function index(Request $request, AuthMemberships $action): JsonResponse
    {
        $query = MembershipIndexQueryData::validateAndCreate(AuthRequestInput::aliased($request->query(), ['per_page' => ['per_page']]));

        return response()->json([
            'data' => $action->paginate($this->subject($request), $query->search, $query->perPage ?? 25),
            'code' => 'memberships_listed', 'message' => trans('nvl-auth::responsecode.memberships_listed'),
        ]);
    }

    public function show(Request $request, string $membership, AuthMemberships $action): JsonResponse
    {
        try {
            $data = $action->find($this->subject($request), $membership);
        } catch (AuthException $exception) {
            if ($exception->status !== 404) {
                throw $exception;
            }

            return response()->json(['data' => null, 'code' => 'membership_unavailable', 'message' => trans('nvl-auth::responsecode.membership_unavailable')], 404);
        }

        return response()->json(['data' => $data, 'code' => 'membership_shown', 'message' => trans('nvl-auth::responsecode.membership_shown')]);
    }

    public function store(Request $request, AuthMemberships $action): JsonResponse
    {
        $data = EnrollMembershipInputData::validateAndCreate(AuthRequestInput::aliased($request->all(), [
            'subject_type' => ['subjectType'],
            'subject_id' => ['subjectId'],
        ]));
        $membership = $action->enroll($this->subject($request), $data->enrollment()->subject, $data->roles, $data->permissions);

        return response()->json(['data' => $membership, 'code' => 'membership_enrolled', 'message' => trans('nvl-auth::responsecode.membership_enrolled')], 201);
    }

    public function status(Request $request, string $membership, AuthMemberships $action): JsonResponse
    {
        $data = UpdateMembershipStatusData::validateAndCreate(AuthRequestInput::aliased($request->all(), ['expected_revision' => ['expected_revision']]));

        return response()->json([
            'data' => $action->setStatus($this->subject($request), $membership, $data->status, $data->expectedRevision),
            'code' => 'membership_status_updated', 'message' => trans('nvl-auth::responsecode.membership_status_updated'),
        ]);
    }

    public function destroy(Request $request, string $membership, AuthMemberships $action): JsonResponse
    {
        $data = MembershipRevisionData::validateAndCreate(AuthRequestInput::aliased($request->all(), ['expected_revision' => ['expected_revision']]));
        $action->revoke($this->subject($request), $membership, $data->expectedRevision);

        return response()->json(['data' => null, 'code' => 'membership_revoked', 'message' => trans('nvl-auth::responsecode.membership_revoked')]);
    }

    public function transfer(Request $request, string $membership, AuthMemberships $action): JsonResponse
    {
        $data = TransferMembershipOwnershipData::validateAndCreate(AuthRequestInput::aliased($request->all(), [
            'recipient_membership_id' => ['recipientMembershipId'],
            'expected_revision' => ['expected_revision'],
        ]));

        return response()->json([
            'data' => $action->transfer($this->subject($request), $membership, $data->recipientMembershipId, $data->expectedRevision),
            'code' => 'membership_ownership_transferred', 'message' => trans('nvl-auth::responsecode.membership_ownership_transferred'),
        ]);
    }
}
