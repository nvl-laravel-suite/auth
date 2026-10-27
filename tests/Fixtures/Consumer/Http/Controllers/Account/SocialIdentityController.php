<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Services\AuthSocialIdentities;

/**
 * Handles account social-identity linking and revocation transport.
 */
final class SocialIdentityController extends AuthenticatedController
{
    /**
     * Start a provider link authorization.
     */
    public function redirect(string $provider, AuthSocialIdentities $action): JsonResponse
    {
        return response()->json(['data' => ['url' => $action->startAuthorization($provider)], 'code' => 'social_link_started', 'message' => trans('nvl-auth::responsecode.social_link_started')]);
    }

    /**
     * Complete a provider link callback for the current subject.
     */
    public function callback(
        Request $request,
        string $provider,
        AuthSocialIdentities $action,
    ): JsonResponse {
        $identity = $action->completeAuthorization($provider, $this->subject($request), grant: $this->recentGrant($request), context: $this->authenticationContext($request));

        return response()->json(['data' => ['social_identity_id' => $identity->identifier(), 'provider' => $identity->provider], 'code' => 'social_identity_linked', 'message' => trans('nvl-auth::responsecode.social_identity_linked')]);
    }

    /**
     * Revoke one linked identity.
     */
    public function destroy(
        Request $request,
        SocialIdentity $socialIdentity,
        AuthSocialIdentities $action,
    ): JsonResponse {
        $action->revoke($this->subject($request), $socialIdentity, grant: $this->recentGrant($request), context: $this->authenticationContext($request));

        return response()->json(['data' => null, 'code' => 'social_identity_revoked', 'message' => trans('nvl-auth::responsecode.social_identity_revoked')]);
    }
}
