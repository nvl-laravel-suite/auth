<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\Authentication\EstablishAuthenticatedSessionAction;
use Nvl\Auth\Actions\Challenges\ConsumeMagicLinkAction;
use Nvl\Auth\Actions\Challenges\RequestMagicLinkAuthenticationAction;
use Nvl\Auth\Actions\Challenges\RequestSecurityCodeAction;
use Nvl\Auth\Actions\Challenges\VerifySecurityCodeAction;
use Nvl\Auth\Http\Controllers\Concerns\InteractsWithValidatedInput;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Handles magic-link and numeric-code challenge transports.
 */
final class ChallengeController
{
    use InteractsWithValidatedInput;

    /**
     * Request a magic link without returning its secret.
     */
    public function requestMagicLink(
        Request $request,
        RequestMagicLinkAuthenticationAction $action,
    ): JsonResponse {
        $request->validate([
            'recipient' => ['required', 'string', 'max:320'],
        ]);
        $action->execute($this->stringInput($request, 'recipient'), $request->getPreferredLanguage());

        return response()->json(['data' => null, 'code' => 'magic_link_requested', 'message' => 'The magic link was requested.'], 202);
    }

    /**
     * Consume a magic link and establish a session when it is subject-bound.
     */
    public function consumeMagicLink(
        Request $request,
        ConsumeMagicLinkAction $action,
        EstablishAuthenticatedSessionAction $sessions,
    ): JsonResponse {
        $request->validate([
            'recipient' => ['required', 'string', 'max:320'],
            'token' => ['required', 'string', 'max:255'],
        ]);
        $challenge = $action->execute(
            $this->stringInput($request, 'recipient'),
            $this->stringInput($request, 'token'),
        );

        if (is_string($challenge->subject_type) && is_string($challenge->subject_id)) {
            $sessions->execute(new SubjectReference($challenge->subject_type, $challenge->subject_id));
        }

        return response()->json(['data' => null, 'code' => 'magic_link_consumed', 'message' => 'The magic link was consumed.']);
    }

    /**
     * Request a numeric security code.
     */
    public function requestSecurityCode(Request $request, RequestSecurityCodeAction $action): JsonResponse
    {
        $request->validate([
            'recipient' => ['required', 'string', 'max:320'],
            'purpose' => ['required', 'string', 'max:120'],
        ]);
        $action->execute(
            $this->stringInput($request, 'recipient'),
            $this->stringInput($request, 'purpose'),
            locale: $request->getPreferredLanguage(),
        );

        return response()->json(['data' => null, 'code' => 'security_code_requested', 'message' => 'The security code was requested.'], 202);
    }

    /**
     * Verify and consume a numeric security code.
     */
    public function verifySecurityCode(Request $request, VerifySecurityCodeAction $action): JsonResponse
    {
        $request->validate([
            'recipient' => ['required', 'string', 'max:320'],
            'purpose' => ['required', 'string', 'max:120'],
            'code' => ['required', 'string', 'max:20'],
        ]);
        $challenge = $action->execute(
            $this->stringInput($request, 'recipient'),
            $this->stringInput($request, 'purpose'),
            $this->stringInput($request, 'code'),
        );

        return response()->json([
            'data' => ['challenge_id' => $challenge->identifier()],
            'code' => 'security_code_verified',
            'message' => 'The security code was verified.',
        ]);
    }
}
