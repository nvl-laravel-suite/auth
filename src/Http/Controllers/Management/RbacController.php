<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Management;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Rbac\SynchronizeRbacAction;
use Nvl\Auth\Http\Controllers\Account\AuthenticatedController;

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
        SynchronizeRbacAction $action,
    ): JsonResponse {
        $actor = $this->subject($request);
        $result = $action->execute($actor);

        return response()->json([
            'data' => $result,
            'code' => 'rbac_synchronized',
            'message' => 'Spatie Permission catalogs were synchronized.',
        ]);
    }
}
