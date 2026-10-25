<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\AcceptInvitationData;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Concerns\InteractsWithValidatedInput;
use Nvl\Auth\ValueObjects\SubjectReference;
use Spatie\LaravelData\Optional;

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
        AcceptInvitationData $data,
        AuthInvitations $register,
        Request $request,
    ): JsonResponse {
        $registered = $register->register(array_filter(get_object_vars($data), static fn ($value): bool => ! $value instanceof Optional), $request->user());
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
