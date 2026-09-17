<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Memberships\ListOwnMembershipsAction;

/** Exposes only the authenticated identity's own membership discovery. */
final class MembershipController extends AuthenticatedController
{
    public function index(Request $request, ListOwnMembershipsAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute($this->subject($request)),
            'code' => 'memberships_listed',
            'message' => 'Memberships were listed.',
        ]);
    }
}
