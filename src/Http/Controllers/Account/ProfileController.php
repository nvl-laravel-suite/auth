<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Users\ShowProfileAction;
use Nvl\Auth\Actions\Users\UpdateProfileAction;
use Nvl\Auth\Data\Mutations\UpdateProfileData;

/** Handles package-owned self-service profile transport. */
final class ProfileController extends AuthenticatedController
{
    /** Show the authenticated principal profile. */
    public function show(Request $request, ShowProfileAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute($this->subject($request)),
            'code' => 'profile_shown',
            'message' => 'The profile was shown.',
        ]);
    }

    public function update(UpdateProfileData $data, Request $request, UpdateProfileAction $action): JsonResponse
    {
        $user = $action->execute($this->subject($request), $data);

        return response()->json([
            'data' => $user,
            'code' => 'profile_updated',
            'message' => 'The profile was updated.',
        ]);
    }
}
