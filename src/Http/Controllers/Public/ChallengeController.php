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
use Nvl\Auth\Data\Mutations\ConsumeMagicLinkData;
use Nvl\Auth\Data\Mutations\RequestMagicLinkData;
use Nvl\Auth\Data\Mutations\RequestSecurityCodeData;
use Nvl\Auth\Data\Mutations\VerifySecurityCodeData;
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
        RequestMagicLinkData $data,
        Request $request,
        RequestMagicLinkAuthenticationAction $action,
    ): JsonResponse {
        $action->execute($data, $request->getPreferredLanguage());

        return response()->json(['data' => null, 'code' => 'magic_link_requested', 'message' => 'The magic link was requested.'], 202);
    }

    /**
     * Consume a magic link and establish a session when it is subject-bound.
     */
    public function consumeMagicLink(
        ConsumeMagicLinkData $data,
        ConsumeMagicLinkAction $action,
        EstablishAuthenticatedSessionAction $sessions,
    ): JsonResponse {
        $challenge = $action->execute($data);

        if (is_string($challenge->subject_type) && is_string($challenge->subject_id)) {
            $sessions->execute(new SubjectReference($challenge->subject_type, $challenge->subject_id));
        }

        return response()->json(['data' => null, 'code' => 'magic_link_consumed', 'message' => 'The magic link was consumed.']);
    }

    /**
     * Request a numeric security code.
     */
    public function requestSecurityCode(
        RequestSecurityCodeData $data,
        Request $request,
        RequestSecurityCodeAction $action
    ): JsonResponse {
        $action->execute(
            $data,
            locale: $request->getPreferredLanguage(),
        );

        return response()->json(['data' => null, 'code' => 'security_code_requested', 'message' => 'The security code was requested.'], 202);
    }

    /**
     * Verify and consume a numeric security code.
     */
    public function verifySecurityCode(VerifySecurityCodeData $data, VerifySecurityCodeAction $action): JsonResponse
    {
        $challenge = $action->execute($data);

        return response()->json([
            'data' => ['challenge_id' => $challenge->identifier()],
            'code' => 'security_code_verified',
            'message' => 'The security code was verified.',
        ]);
    }
}
