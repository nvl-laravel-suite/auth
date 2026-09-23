<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Memberships\EnrollMembershipAction;
use Nvl\Auth\Actions\Memberships\ListMembershipsAction;
use Nvl\Auth\Actions\Memberships\RevokeMembershipAction;
use Nvl\Auth\Actions\Memberships\SetMembershipStatusAction;
use Nvl\Auth\Actions\Memberships\ShowMembershipAction;
use Nvl\Auth\Actions\Memberships\TransferMembershipOwnershipAction;
use Nvl\Auth\Data\Mutations\EnrollMembershipInputData;
use Nvl\Auth\Data\Mutations\MembershipRevisionData;
use Nvl\Auth\Data\Mutations\TransferMembershipOwnershipData;
use Nvl\Auth\Data\Mutations\UpdateMembershipStatusData;
use Nvl\Auth\Data\Queries\MembershipIndexQueryData;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Http\AuthRequestInput;
use Nvl\Auth\Http\Controllers\Account\AuthenticatedController;

/** Handles tenant membership management transport. */
final class MembershipController extends AuthenticatedController
{
    public function index(Request $request, ListMembershipsAction $action): JsonResponse
    {
        $query = MembershipIndexQueryData::validateAndCreate(AuthRequestInput::aliased($request->query(), ['per_page' => ['perPage']]));

        return response()->json([
            'data' => $action->execute($this->subject($request), $query->search, $query->perPage ?? 25),
            'code' => 'memberships_listed',
            'message' => 'Memberships were listed.',
        ]);
    }

    public function show(Request $request, string $membership, ShowMembershipAction $action): JsonResponse
    {
        try {
            $data = $action->execute($this->subject($request), $membership);
        } catch (AuthException $exception) {
            if ($exception->status !== 404) {
                throw $exception;
            }

            return response()->json(['data' => null, 'code' => 'membership_unavailable', 'message' => 'The tenant membership is unavailable.'], 404);
        }

        return response()->json(['data' => $data, 'code' => 'membership_shown', 'message' => 'The membership was shown.']);
    }

    public function store(Request $request, EnrollMembershipAction $action): JsonResponse
    {
        $data = EnrollMembershipInputData::validateAndCreate(AuthRequestInput::aliased($request->all(), [
            'subject_type' => ['subjectType'],
            'subject_id' => ['subjectId'],
        ]));
        $membership = $action->execute($this->subject($request), $data->enrollment());

        return response()->json(['data' => $membership, 'code' => 'membership_enrolled', 'message' => 'The membership was enrolled.'], 201);
    }

    public function status(Request $request, string $membership, SetMembershipStatusAction $action): JsonResponse
    {
        $data = UpdateMembershipStatusData::validateAndCreate(AuthRequestInput::aliased($request->all(), ['expected_revision' => ['expectedRevision']]));

        return response()->json([
            'data' => $action->execute($this->subject($request), $membership, $data),
            'code' => 'membership_status_updated', 'message' => 'The membership status was updated.',
        ]);
    }

    public function destroy(Request $request, string $membership, RevokeMembershipAction $action): JsonResponse
    {
        $data = MembershipRevisionData::validateAndCreate(AuthRequestInput::aliased($request->all(), ['expected_revision' => ['expectedRevision']]));
        $action->execute($this->subject($request), $membership, $data->expectedRevision);

        return response()->json(['data' => null, 'code' => 'membership_revoked', 'message' => 'The membership was revoked.']);
    }

    public function transfer(Request $request, string $membership, TransferMembershipOwnershipAction $action): JsonResponse
    {
        $data = TransferMembershipOwnershipData::validateAndCreate(AuthRequestInput::aliased($request->all(), [
            'recipient_membership_id' => ['recipientMembershipId'],
            'expected_revision' => ['expectedRevision'],
        ]));

        return response()->json([
            'data' => $action->execute($this->subject($request), $membership, $data),
            'code' => 'membership_ownership_transferred', 'message' => 'Membership ownership was transferred.',
        ]);
    }
}
