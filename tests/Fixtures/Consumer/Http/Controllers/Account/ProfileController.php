<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Services\AuthEmailChanges;
use Nvl\Auth\Services\AuthUserReader;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Services\PrincipalEmailIdentity;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\DeleteOwnAccountData;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\UpdateProfileData;

/** Handles package-owned self-service profile transport. */
final class ProfileController extends AuthenticatedController
{
    /** Show the authenticated principal profile. */
    public function show(Request $request, AuthUserReader $action): JsonResponse
    {
        return response()->json([
            'data' => $action->profile($this->subject($request)),
            'code' => 'profile_shown', 'message' => trans('nvl-auth::responsecode.profile_shown'),
        ]);
    }

    public function update(Request $request, AuthUsers $action, AuthEmailChanges $emails): JsonResponse
    {
        $data = Validator::make($request->all(), UpdateProfileData::rules())->validate();

        $input = $data;
        if (is_string($input['email'] ?? null) && PrincipalEmailIdentity::normalize($input['email']) !== PrincipalEmailIdentity::normalize($this->subject($request)->getEmailForVerification())) {
            $pending = $emails->request($this->subject($request), $input['email'], $this->recentGrant($request), $this->authenticationContext($request));
            unset($input['email']);
            if ($input !== []) {
                $action->updateProfile($this->subject($request), $input);
            }

            return response()->json(['data' => ['change_id' => $pending->identifier()], 'code' => 'email_change_pending'], 202);
        }
        $user = $action->updateProfile($this->subject($request), $data, grant: $this->recentGrant($request), context: $request->hasSession() ? $this->authenticationContext($request) : null);

        return response()->json([
            'data' => $user,
            'code' => 'profile_updated', 'message' => trans('nvl-auth::responsecode.profile_updated'),
        ]);
    }

    /** Confirm and delete the authenticated principal. */
    public function destroy(
        Request $request,
        AuthUsers $action,
    ): JsonResponse {
        $data = Validator::make($request->all(), DeleteOwnAccountData::rules())->validate();

        $action->deleteOwnAccount($this->subject($request), [], auth()->guard(config('nvl-auth.authorization.guard', 'web')), $request->session(), grant: $this->recentGrant($request), context: $this->authenticationContext($request));

        return response()->json([
            'data' => null,
            'code' => 'account_deleted', 'message' => trans('nvl-auth::responsecode.account_deleted'),
        ]);
    }
}
