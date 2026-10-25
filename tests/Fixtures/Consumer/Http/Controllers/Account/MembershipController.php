<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Services\AuthMemberships;

/** Exposes only the authenticated identity's own membership discovery. */
final class MembershipController extends AuthenticatedController
{
    public function index(Request $request, AuthMemberships $action): JsonResponse
    {
        return response()->json([
            'data' => $action->own($this->subject($request)),
            'code' => 'memberships_listed', 'message' => trans('nvl-auth::responsecode.memberships_listed'),
        ]);
    }
}
