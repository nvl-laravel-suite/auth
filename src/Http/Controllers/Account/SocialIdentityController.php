<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\SocialIdentities\CompleteSocialAuthorizationAction;
use Nvl\Auth\Actions\SocialIdentities\RevokeSocialIdentityAction;
use Nvl\Auth\Actions\SocialIdentities\StartSocialAuthorizationAction;
use Nvl\Auth\Models\SocialIdentity;

/**
 * Handles account social-identity linking and revocation transport.
 */
final class SocialIdentityController extends AuthenticatedController
{
    /**
     * Start a provider link authorization.
     */
    public function redirect(string $provider, StartSocialAuthorizationAction $action): JsonResponse
    {
        return response()->json(['data' => ['url' => $action->execute($provider)], 'code' => 'social_link_started', 'message' => 'Social identity linking was started.']);
    }

    /**
     * Complete a provider link callback for the current subject.
     */
    public function callback(
        Request $request,
        string $provider,
        CompleteSocialAuthorizationAction $action,
    ): JsonResponse {
        $identity = $action->execute($provider, $this->subject($request));

        return response()->json(['data' => ['social_identity_id' => $identity->identifier(), 'provider' => $identity->provider], 'code' => 'social_identity_linked', 'message' => 'The social identity was linked.']);
    }

    /**
     * Revoke one linked identity.
     */
    public function destroy(
        Request $request,
        SocialIdentity $socialIdentity,
        RevokeSocialIdentityAction $action,
    ): JsonResponse {
        $action->execute($this->subject($request), $socialIdentity);

        return response()->json(['data' => null, 'code' => 'social_identity_revoked', 'message' => 'The social identity was revoked.']);
    }
}
