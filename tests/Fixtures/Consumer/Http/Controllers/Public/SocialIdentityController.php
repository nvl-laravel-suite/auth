<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Enums\OwnerAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthSocialAuthentication;
use Nvl\Auth\Services\OwnerAuthenticationIntents;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/** Host-owned Socialite redirect, state and callback transport. */
final class SocialIdentityController
{
    public function redirect(string $provider, Request $request, AuthSocialAuthentication $social, AuthenticationSessions $sessions): JsonResponse
    {
        $sessions->assertCanTransition();
        $owner = $request->attributes->get('owner');
        $returnPath = $request->query('return_path');
        $issued = $owner instanceof OwnerReference ? app(OwnerAuthenticationIntents::class)->issue($owner, OwnerAuthenticationPurpose::SocialLogin, $request->session()->getId(), provider: $provider, returnPath: is_string($returnPath) ? $returnPath : null) : null;
        $context = new AuthenticationRequestContext(ownerIntentNonce: $issued['nonce'] ?? null, ownerSessionBinding: $request->session()->getId(), requestedOwner: $owner instanceof OwnerReference ? $owner : null, ownerPurpose: OwnerAuthenticationPurpose::SocialLogin, ownerProvider: $provider, guardName: config('nvl-auth.authorization.guard', 'web'), sessionBinding: $request->session()->getId());
        $started = $social->beginLogin($provider, $context);
        $url = $started['url'];
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        $state = $query['state'] ?? null;
        if (! is_string($state) || $state === '') {
            throw AuthException::invalidConfiguration('Social login requires SDK-managed OAuth state.');
        }
        $request->session()->put('native-social.'.hash('sha256', $provider.':'.$state), ['intent' => $started['intent']->reveal(), 'context' => $context]);

        return response()->json(['data' => ['url' => $url], 'code' => 'social_authorization_started', 'message' => trans('nvl-auth::responsecode.social_authorization_started')]);
    }

    public function callback(string $provider, Request $request, AuthSocialAuthentication $social, AuthenticationSessions $sessions, AuthSubjectResolver $subjects): JsonResponse
    {
        $sessions->assertCanTransition();
        $state = $request->query('state');
        $pending = is_string($state) ? $request->session()->pull('native-social.'.hash('sha256', $provider.':'.$state)) : null;
        if (! is_array($pending) || ! is_string($pending['intent'] ?? null) || ! ($pending['context'] ?? null) instanceof AuthenticationRequestContext) {
            throw new AuthException('authentication_proof_invalid', 'The social authentication intent is unavailable.', 422);
        }
        $context = $pending['context'];
        $owner = $request->attributes->get('owner');
        if ($context->sessionBinding !== $request->session()->getId() || $context->requestedOwner != ($owner instanceof OwnerReference ? $owner : null)) {
            throw new AuthException('authentication_binding_invalid', 'The social authentication binding changed.', 422);
        }
        $result = $social->completeLogin($provider, $pending['intent'], $context);
        if ($result['status'] === 'registration_required') {
            $request->session()->put('native-social-registration', $result['continuation']->reveal());

            return response()->json(['data' => null, 'code' => 'social_registration_required'], 202);
        }
        $proof = $result['proof'];
        $subject = $sessions->establishFromProof($proof->reveal(), auth()->guard(config('nvl-auth.authorization.guard', 'web')), $request->session(), $context);
        $reference = SubjectReference::fromAuthenticatable($subject);

        return response()->json(['data' => ['subject' => ['type' => $reference->type, 'id' => $reference->identifier]], 'code' => 'social_authenticated', 'message' => trans('nvl-auth::responsecode.social_authenticated')]);
    }
}
