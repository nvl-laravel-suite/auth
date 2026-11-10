<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthMemberships;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\EnrollMembershipInputData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\MembershipRevisionData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\TransferMembershipOwnershipData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\UpdateMembershipStatusData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Queries\MembershipIndexQueryData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\AuthRequestInput;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account\AuthenticatedController;
use Nvl\Auth\ValueObjects\SubjectReference;

/** Handles tenant membership management transport. */
final class MembershipController extends AuthenticatedController
{
    public function index(Request $request, AuthMemberships $action): JsonResponse
    {
        $query = array_replace(['search' => null, 'per_page' => null], Validator::make(AuthRequestInput::aliased($request->query(), ['per_page' => ['perPage']]), MembershipIndexQueryData::rules())->validate());
        if (isset($query['per_page'])) {
            $query['per_page'] = (int) $query['per_page'];
        }

        return response()->json([
            'data' => $action->paginate($this->subject($request), $query['search'], $query['per_page'] ?? 25),
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
        $data = array_replace(['roles' => [], 'permissions' => []], Validator::make(AuthRequestInput::aliased($request->all(), ['subject_type' => ['subjectType'], 'subject_id' => ['subjectId']]), EnrollMembershipInputData::rules())->validate());
        $membership = $action->enroll($this->subject($request), new SubjectReference($data['subject_type'], $data['subject_id']), $data['roles'], $data['permissions']);

        return response()->json(['data' => $membership, 'code' => 'membership_enrolled', 'message' => trans('nvl-auth::responsecode.membership_enrolled')], 201);
    }

    public function status(Request $request, string $membership, AuthMemberships $action): JsonResponse
    {
        $data = Validator::make(AuthRequestInput::aliased($request->all(), ['expected_revision' => ['expectedRevision']]), UpdateMembershipStatusData::rules())->validate();
        if (isset($data['expected_revision'])) {
            $data['expected_revision'] = (int) $data['expected_revision'];
        }

        return response()->json([
            'data' => $action->setStatus($this->subject($request), $membership, MembershipStatus::from($data['status']), $data['expected_revision']),
            'code' => 'membership_status_updated', 'message' => trans('nvl-auth::responsecode.membership_status_updated'),
        ]);
    }

    public function destroy(Request $request, string $membership, AuthMemberships $action): JsonResponse
    {
        $data = Validator::make(AuthRequestInput::aliased($request->all(), ['expected_revision' => ['expectedRevision']]), MembershipRevisionData::rules())->validate();
        if (isset($data['expected_revision'])) {
            $data['expected_revision'] = (int) $data['expected_revision'];
        }

        $action->revoke($this->subject($request), $membership, $data['expected_revision']);

        return response()->json(['data' => null, 'code' => 'membership_revoked', 'message' => trans('nvl-auth::responsecode.membership_revoked')]);
    }

    public function transfer(Request $request, string $membership, AuthMemberships $action): JsonResponse
    {
        $data = Validator::make(AuthRequestInput::aliased($request->all(), ['recipient_membership_id' => ['recipientMembershipId'], 'expected_revision' => ['expectedRevision']]), TransferMembershipOwnershipData::rules())->validate();
        if (isset($data['expected_revision'])) {
            $data['expected_revision'] = (int) $data['expected_revision'];
        }

        return response()->json([
            'data' => $action->transfer($this->subject($request), $membership, $data['recipient_membership_id'], $data['expected_revision']),
            'code' => 'membership_ownership_transferred', 'message' => trans('nvl-auth::responsecode.membership_ownership_transferred'),
        ]);
    }
}
