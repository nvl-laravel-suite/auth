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
use Nvl\Auth\Data\Mutations\EnrollMembershipData;
use Nvl\Auth\Data\Mutations\TransferMembershipOwnershipData;
use Nvl\Auth\Data\Mutations\UpdateMembershipStatusData;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Http\Controllers\Account\AuthenticatedController;
use Nvl\Auth\ValueObjects\SubjectReference;

/** Handles tenant membership management transport. */
final class MembershipController extends AuthenticatedController
{
    public function index(Request $request, ListMembershipsAction $action): JsonResponse
    {
        /** @var array{search?: string|null, per_page?: int|null} $validated */
        $validated = $request->validate(['search' => ['nullable', 'string', 'max:191'], 'per_page' => ['nullable', 'integer', 'min:1', 'max:100']]);

        return response()->json([
            'data' => $action->execute($this->subject($request), $validated['search'] ?? null, $validated['per_page'] ?? 25),
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
        /** @var array{subject_type: string, subject_id: string, roles?: list<string>, permissions?: list<string>} $validated */
        $validated = $request->validate([
            'subject_type' => ['required', 'string', 'max:160'],
            'subject_id' => ['required', 'string', 'max:191'],
            'roles' => ['sometimes', 'array', 'max:100'], 'roles.*' => ['string', 'max:160', 'distinct'],
            'permissions' => ['sometimes', 'array', 'max:100'], 'permissions.*' => ['string', 'max:160', 'distinct'],
        ]);
        $membership = $action->execute($this->subject($request), new EnrollMembershipData(
            new SubjectReference($validated['subject_type'], $validated['subject_id']),
            $validated['roles'] ?? [],
            $validated['permissions'] ?? [],
        ));

        return response()->json(['data' => $membership, 'code' => 'membership_enrolled', 'message' => 'The membership was enrolled.'], 201);
    }

    public function status(Request $request, string $membership, SetMembershipStatusAction $action): JsonResponse
    {
        /** @var array{status: string, expected_revision: int} $validated */
        $validated = $request->validate(['status' => ['required', 'string'], 'expected_revision' => ['required', 'integer', 'min:1']]);
        $status = MembershipStatus::tryFrom($validated['status']);
        abort_if($status === null, 422, 'The membership status is invalid.');

        return response()->json([
            'data' => $action->execute($this->subject($request), $membership, new UpdateMembershipStatusData($status, $validated['expected_revision'])),
            'code' => 'membership_status_updated', 'message' => 'The membership status was updated.',
        ]);
    }

    public function destroy(Request $request, string $membership, RevokeMembershipAction $action): JsonResponse
    {
        /** @var array{expected_revision: int} $validated */
        $validated = $request->validate(['expected_revision' => ['required', 'integer', 'min:1']]);
        $action->execute($this->subject($request), $membership, $validated['expected_revision']);

        return response()->json(['data' => null, 'code' => 'membership_revoked', 'message' => 'The membership was revoked.']);
    }

    public function transfer(Request $request, string $membership, TransferMembershipOwnershipAction $action): JsonResponse
    {
        /** @var array{recipient_membership_id: string, expected_revision: int} $validated */
        $validated = $request->validate(['recipient_membership_id' => ['required', 'uuid'], 'expected_revision' => ['required', 'integer', 'min:1']]);

        return response()->json([
            'data' => $action->execute($this->subject($request), $membership, new TransferMembershipOwnershipData($validated['recipient_membership_id'], $validated['expected_revision'])),
            'code' => 'membership_ownership_transferred', 'message' => 'Membership ownership was transferred.',
        ]);
    }
}
