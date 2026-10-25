<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthPasskeys;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\FinishPasskeyAuthenticationData;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/** Host-owned HTTP ceremony and session transport. */
final class PasskeyController
{
    public function begin(Request $request, AuthPasskeys $passkeys): JsonResponse
    {
        $options = $passkeys->beginAuthentication(owner: $this->owner($request), sessionBinding: $request->session()->getId());

        return response()->json(['data' => ['ceremony_id' => $options->ceremonyId, 'options' => $options->options, 'expires_at' => $options->expiresAt->toIso8601String()], 'code' => 'passkey_authentication_started', 'message' => trans('nvl-auth::responsecode.passkey_authentication_started')]);
    }

    public function finish(FinishPasskeyAuthenticationData $data, Request $request, AuthPasskeys $passkeys, AuthenticationSessions $sessions, AuthSubjectResolver $subjects): JsonResponse
    {
        $completed = $passkeys->finishAuthentication(get_object_vars($data), $this->owner($request), $request->session()->getId());
        $reference = $completed['subject'];
        $subject = $subjects->resolve($reference) ?? throw new AuthException('subject_unavailable', 'The authenticated principal is unavailable.', 422);
        $sessions->establishForPurpose($subject, auth()->guard(config('nvl-auth.guard', 'web')), $request->session(), AuthenticationPurpose::PasswordlessLogin, $completed['requestContext'] ?? new AuthenticationRequestContext(ipAddress: $request->ip(), userAgent: $request->userAgent(), requestId: $request->header('X-Request-ID')));

        return response()->json(['data' => ['subject' => ['type' => $reference->type, 'id' => $reference->identifier]], 'code' => 'passkey_authenticated', 'message' => trans('nvl-auth::responsecode.passkey_authenticated')]);
    }

    private function owner(Request $request): ?OwnerReference
    {
        $owner = $request->attributes->get('owner');

        return $owner instanceof OwnerReference ? $owner : null;
    }
}
