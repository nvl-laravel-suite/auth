<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Services\AuthChallenges;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;

/** Host transport fixture: validation, throttling, sessions and response secrecy. */
final class ChallengeController
{
    public function requestMagicLink(Request $request, AuthChallenges $challenges, Timebox $timebox): JsonResponse
    {
        $data = $request->validate(['recipient' => ['required', 'email'], 'purpose' => ['sometimes', 'string']]);
        $timebox->dontReturnEarly()->call(fn () => $challenges->requestMagicLinkAuthentication($data, $this->context($request), $request->getPreferredLanguage()), 200000);

        return $this->response('magic_link_requested', 202);
    }

    public function consumeMagicLink(Request $request, AuthChallenges $challenges, AuthenticationSessions $sessions, AuthSubjectResolver $subjects): JsonResponse
    {
        $data = $request->validate(['recipient' => ['nullable', 'email'], 'token' => ['required', 'string'], 'challengeId' => ['nullable', 'string']]);
        $context = $this->context($request);
        $proof = $challenges->consumeMagicLinkAuthentication(['recipient' => null, ...$data], $context);
        $sessions->establishFromProof($proof->reveal(), auth()->guard('web'), $request->session(), $context);

        return $this->response('magic_link_consumed');
    }

    public function requestSecurityCode(Request $request, AuthChallenges $challenges): JsonResponse
    {
        $challenges->requestSecurityCode($request->validate(['recipient' => ['required', 'email'], 'purpose' => ['required', 'string']]), locale: $request->getPreferredLanguage());

        return $this->response('security_code_requested', 202);
    }

    public function verifySecurityCode(Request $request, AuthChallenges $challenges): JsonResponse
    {
        $challenge = $challenges->verifySecurityCode($request->validate(['recipient' => ['required', 'email'], 'purpose' => ['required', 'string'], 'code' => ['required', 'string']]));

        return $this->response('security_code_verified', data: ['challenge_id' => $challenge->identifier()]);
    }

    public function requestSecurityCodeAuthentication(Request $request, AuthChallenges $challenges, Timebox $timebox): JsonResponse
    {
        $data = $request->validate(['recipient' => ['required', 'email'], 'purpose' => ['required', 'string']]);
        $timebox->dontReturnEarly()->call(fn () => $challenges->requestSecurityCodeAuthentication($data, $this->context($request), $request->getPreferredLanguage()), 200000);

        return $this->response('security_code_authentication_requested', 202);
    }

    public function verifySecurityCodeAuthentication(Request $request, AuthChallenges $challenges): JsonResponse
    {
        $challenge = $challenges->verifySecurityCodeAuthentication($request->validate(['recipient' => ['required', 'email'], 'purpose' => ['required', 'string'], 'code' => ['required', 'string']]), auth()->guard('web'), $request->session(), $this->context($request));

        return $this->response('security_code_authenticated', data: ['subject_id' => (string) $challenge->getAuthIdentifier()]);
    }

    private function context(Request $request): AuthenticationRequestContext
    {
        return new AuthenticationRequestContext(guardName: 'web', sessionBinding: $request->session()->getId());
    }

    /** @param array<string, string>|null $data */
    private function response(string $code, int $status = 200, ?array $data = null): JsonResponse
    {
        return response()->json(['data' => $data, 'code' => $code, 'message' => trans('nvl-auth::responsecode.'.$code)], $status);
    }
}
