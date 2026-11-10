<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\AcceptInvitationData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\AuthRequestInput;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Concerns\InteractsWithValidatedInput;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Handles public invitation acceptance through a host subject resolver.
 */
final class InvitationController
{
    use InteractsWithValidatedInput;

    /**
     * Provision or resolve the host subject and consume the invitation.
     */
    public function accept(
        AuthInvitations $register,
        Request $request,
    ): JsonResponse {
        $data = array_replace(['registrationMethod' => 'password', 'locale' => null, 'timezone' => null, 'extensions' => []], Validator::make(AuthRequestInput::aliased($request->all(), ['registrationMethod' => ['registration_method'], 'passwordConfirmation' => ['password_confirmation']]), AcceptInvitationData::rules())->validate());

        $registered = $register->register($data, $request->user());
        $reference = SubjectReference::fromAuthenticatable($registered['subject']);

        return response()->json([
            'data' => [
                'invitation_id' => $registered['invitation']->identifier(),
                'subject' => ['type' => $reference->type, 'id' => $reference->identifier],
            ],
            'code' => 'invitation_accepted', 'message' => trans('nvl-auth::responsecode.invitation_accepted'),
        ]);
    }
}
