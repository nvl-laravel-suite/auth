<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\LoginData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Concerns\InteractsWithValidatedInput;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Handles public password authentication transport concerns.
 */
final class AuthenticationController
{
    use InteractsWithValidatedInput;

    /**
     * Authenticate one browser user.
     */
    public function login(Request $request, Authentication $action): JsonResponse
    {
        $data = array_replace(['remember' => false], Validator::make($request->all(), LoginData::rules())->validate());
        if (isset($data['remember'])) {
            $data['remember'] = (bool) $data['remember'];
        }

        $subject = $action->login(['identifier' => $data['identifier'], 'password' => $data['password']], [
            'remember' => $data['remember'],
            'ipAddress' => $request->ip(), 'userAgent' => $request->userAgent(),
            'requestId' => $request->headers->get('X-Request-ID'),
        ], auth()->guard(config('nvl-auth.authorization.guard', 'web')), $request->session());
        $reference = SubjectReference::fromAuthenticatable($subject);

        return response()->json([
            'data' => ['subject' => ['type' => $reference->type, 'id' => $reference->identifier]],
            'code' => 'authenticated', 'message' => trans('nvl-auth::responsecode.authenticated'),
        ]);
    }
}
