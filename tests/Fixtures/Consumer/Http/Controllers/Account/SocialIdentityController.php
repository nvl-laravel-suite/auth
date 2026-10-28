<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Services\AuthSocialLinks;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;

/**
 * Handles account social-identity linking and revocation transport.
 */
final class SocialIdentityController extends AuthenticatedController
{
    /**
     * Start a provider link authorization.
     */
    public function redirect(string $provider, Request $request, AuthSocialLinks $action): JsonResponse
    {
        $context = $this->authenticationContext($request);
        $started = $action->beginLink($this->subject($request), $provider, $this->recentGrant($request), $context);
        $request->session()->put('native-social-link.'.$provider, ['intent' => $started['intent']->reveal(), 'context' => $context]);

        return response()->json(['data' => ['url' => $started['url']], 'code' => 'social_link_started', 'message' => trans('nvl-auth::responsecode.social_link_started')]);
    }

    /**
     * Complete a provider link callback for the current subject.
     */
    public function callback(
        Request $request,
        string $provider,
        AuthSocialLinks $action,
    ): JsonResponse {
        $pending = $request->session()->pull('native-social-link.'.$provider);
        if (! is_array($pending) || ! is_string($pending['intent'] ?? null) || ! ($pending['context'] ?? null) instanceof AuthenticationRequestContext) {
            throw new AuthException('social_intent_invalid', 'Restart social linking.', 422);
        }
        if ($pending['context']->sessionBinding !== $request->session()->getId()) {
            throw new AuthException('social_intent_invalid', 'Restart social linking.', 422);
        }
        $identity = $action->completeLink($this->subject($request), $provider, $pending['intent'], $pending['context']);

        return response()->json(['data' => ['social_identity_id' => $identity->identifier(), 'provider' => $identity->provider], 'code' => 'social_identity_linked', 'message' => trans('nvl-auth::responsecode.social_identity_linked')]);
    }

    /**
     * Revoke one linked identity.
     */
    public function destroy(
        Request $request,
        SocialIdentity $socialIdentity,
        AuthSocialLinks $action,
    ): JsonResponse {
        $action->unlink($this->subject($request), $socialIdentity->identifier(), $this->recentGrant($request), $this->authenticationContext($request));

        return response()->json(['data' => null, 'code' => 'social_identity_revoked', 'message' => trans('nvl-auth::responsecode.social_identity_revoked')]);
    }
}
