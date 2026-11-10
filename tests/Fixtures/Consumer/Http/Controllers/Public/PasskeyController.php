<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthPasskeys;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\FinishPasskeyAuthenticationData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\AuthRequestInput;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/** Host-owned HTTP ceremony and session transport. */
final class PasskeyController
{
    public function begin(Request $request, AuthPasskeys $passkeys, AuthenticationSessions $sessions): JsonResponse
    {
        $sessions->assertCanTransition();
        $options = $passkeys->beginAuthentication(owner: $this->owner($request), sessionBinding: $request->session()->getId(), context: new AuthenticationRequestContext(guardName: config('nvl-auth.authorization.guard', 'web'), sessionBinding: $request->session()->getId()));

        return response()->json(['data' => ['ceremony_id' => $options->ceremonyId, 'options' => $options->options, 'expires_at' => $options->expiresAt->toIso8601String()], 'code' => 'passkey_authentication_started', 'message' => trans('nvl-auth::responsecode.passkey_authentication_started')]);
    }

    public function finish(Request $request, AuthPasskeys $passkeys, AuthenticationSessions $sessions, AuthSubjectResolver $subjects): JsonResponse
    {
        $data = Validator::make(AuthRequestInput::aliased($request->all(), ['ceremonyId' => ['ceremony_id']]), FinishPasskeyAuthenticationData::rules())->validate();

        $sessions->assertCanTransition();
        $completed = $passkeys->finishAuthentication($data, $this->owner($request), $request->session()->getId());
        $reference = $completed['subject'];
        $sessions->establishFromProof($completed['proof']->reveal(), auth()->guard(config('nvl-auth.authorization.guard', 'web')), $request->session(), $completed['requestContext']);

        return response()->json(['data' => ['subject' => ['type' => $reference->type, 'id' => $reference->identifier]], 'code' => 'passkey_authenticated', 'message' => trans('nvl-auth::responsecode.passkey_authenticated')]);
    }

    private function owner(Request $request): ?OwnerReference
    {
        $owner = $request->attributes->get('owner');

        return $owner instanceof OwnerReference ? $owner : null;
    }
}
