<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Services\AuthPermissions;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account\AuthenticatedController;

/**
 * Handles authorized Spatie Permission synchronization transport.
 */
final class RbacController extends AuthenticatedController
{
    /**
     * Synchronize permission catalogs and role templates.
     */
    public function synchronize(
        Request $request,
        AuthPermissions $action,
    ): JsonResponse {
        $actor = $this->subject($request);
        $result = $action->synchronize($actor);

        return response()->json([
            'data' => $result,
            'code' => 'rbac_synchronized', 'message' => trans('nvl-auth::responsecode.rbac_synchronized'),
        ]);
    }
}
