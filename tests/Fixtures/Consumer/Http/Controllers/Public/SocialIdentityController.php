<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Enums\OwnerAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthSocialIdentities;
use Nvl\Auth\Services\OwnerAuthenticationIntents;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/** Host-owned Socialite redirect, state and callback transport. */
final class SocialIdentityController
{
    public function redirect(string $provider, Request $request, AuthSocialIdentities $social, OwnerAuthenticationIntents $intents): JsonResponse
    {
        $url = $social->startAuthorization($provider);
        $owner = $request->attributes->get('owner');
        if ($owner instanceof OwnerReference) {
            parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
            $state = $query['state'] ?? null;
            if (! is_string($state) || $state === '') {
                throw AuthException::invalidConfiguration('Owner social login requires SDK-managed OAuth state.');
            }
            $returnPath = $request->query('return_path');
            $issued = $intents->issue($owner, OwnerAuthenticationPurpose::SocialLogin, $request->session()->getId(), provider: $provider, returnPath: is_string($returnPath) ? $returnPath : null);
            $request->session()->put('owner-social.'.hash('sha256', $provider.':'.$state), $issued['nonce']);
        }

        return response()->json(['data' => ['url' => $url], 'code' => 'social_authorization_started', 'message' => trans('nvl-auth::responsecode.social_authorization_started')]);
    }

    public function callback(string $provider, Request $request, AuthSocialIdentities $social, AuthenticationSessions $sessions, AuthSubjectResolver $subjects): JsonResponse
    {
        $identity = $social->completeAuthorization($provider);
        $reference = new SubjectReference($identity->subject_type, $identity->subject_id);
        $subject = $subjects->resolve($reference) ?? throw new AuthException('subject_unavailable', 'The authenticated principal is unavailable.', 422);
        $state = $request->query('state');
        $nonce = is_string($state) ? $request->session()->pull('owner-social.'.hash('sha256', $provider.':'.$state)) : null;
        $owner = $request->attributes->get('owner');
        $context = new AuthenticationRequestContext(ipAddress: $request->ip(), userAgent: $request->userAgent(), requestId: $request->header('X-Request-ID'), ownerIntentNonce: is_string($nonce) ? $nonce : null, ownerSessionBinding: $request->session()->getId(), requestedOwner: $owner instanceof OwnerReference ? $owner : null, ownerPurpose: OwnerAuthenticationPurpose::SocialLogin, ownerProvider: $provider);
        $sessions->establishForPurpose($subject, auth()->guard(config('nvl-auth.guard', 'web')), $request->session(), AuthenticationPurpose::SocialLogin, $context);

        return response()->json(['data' => ['subject' => ['type' => $reference->type, 'id' => $reference->identifier]], 'code' => 'social_authenticated', 'message' => trans('nvl-auth::responsecode.social_authenticated')]);
    }
}
