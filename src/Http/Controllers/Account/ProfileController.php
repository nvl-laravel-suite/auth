<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Users\ShowProfileAction;
use Nvl\Auth\Actions\Users\UpdateProfileAction;
use Nvl\Auth\Http\Requests\UpdateProfileRequest;
use Nvl\Auth\ValueObjects\ProfileData;

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

    /** Update the authenticated principal profile. */
    public function update(UpdateProfileRequest $request, UpdateProfileAction $action): JsonResponse
    {
        $user = $action->execute($this->subject($request), new ProfileData(
            name: $this->stringInput($request, 'name'),
            locale: $this->stringInput($request, 'locale'),
            timezone: $this->stringInput($request, 'timezone'),
            profile: $this->associativeInput($request, 'profile'),
            preferences: $this->associativeInput($request, 'preferences'),
        ));

        return response()->json([
            'data' => $user,
            'code' => 'profile_updated',
            'message' => 'The profile was updated.',
        ]);
    }
}
