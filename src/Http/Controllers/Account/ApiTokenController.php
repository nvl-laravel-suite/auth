<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Actions\ApiTokens\CreateApiTokenAction;
use Nvl\Auth\Actions\ApiTokens\ListApiTokensAction;
use Nvl\Auth\Actions\ApiTokens\RevokeAllApiTokensAction;
use Nvl\Auth\Actions\ApiTokens\RevokeApiTokenAction;
use Nvl\Auth\Actions\ApiTokens\RotateApiTokenAction;
use Nvl\Auth\Actions\ApiTokens\UpdateApiTokenAction;
use Nvl\Auth\Data\Mutations\ApiTokenData;
use Nvl\Auth\ValueObjects\ApiTokenSnapshot;

/**
 * Handles Sanctum-backed personal API token transport.
 */
final class ApiTokenController extends AuthenticatedController
{
    /**
     * List subject-owned provider tokens.
     */
    public function index(Request $request, ListApiTokensAction $action): JsonResponse
    {
        $tokens = array_map($this->snapshot(...), $action->execute($this->subject($request)));

        return response()->json(['data' => $tokens, 'code' => 'api_tokens_listed', 'message' => 'API tokens were listed.']);
    }

    /**
     * Issue one provider token.
     */
    public function store(ApiTokenData $data, Request $request, CreateApiTokenAction $action): JsonResponse
    {
        $issued = $action->execute($this->subject($request), $data);

        return response()->json([
            'data' => [...$this->snapshot($issued->token), 'plain_text_token' => $issued->plainTextToken],
            'code' => 'api_token_issued',
            'message' => 'The API token was issued.',
        ], 201);
    }

    /**
     * Update one provider token.
     */
    public function update(
        ApiTokenData $data,
        Request $request,
        string $tokenId,
        UpdateApiTokenAction $action,
    ): JsonResponse {
        $token = $action->execute($this->subject($request), $tokenId, $data);

        return response()->json(['data' => $this->snapshot($token), 'code' => 'api_token_updated', 'message' => 'The API token was updated.']);
    }

    /**
     * Rotate one provider token.
     */
    public function rotate(
        ApiTokenData $data,
        Request $request,
        string $tokenId,
        RotateApiTokenAction $action,
    ): JsonResponse {
        $issued = $action->execute($this->subject($request), $tokenId, $data);

        return response()->json([
            'data' => [...$this->snapshot($issued->token), 'plain_text_token' => $issued->plainTextToken],
            'code' => 'api_token_rotated',
            'message' => 'The API token was rotated.',
        ]);
    }

    /**
     * Revoke one provider token.
     */
    public function destroy(
        Request $request,
        string $tokenId,
        RevokeApiTokenAction $action,
    ): JsonResponse {
        $action->execute($this->subject($request), $tokenId);

        return response()->json(['data' => null, 'code' => 'api_token_revoked', 'message' => 'The API token was revoked.']);
    }

    /**
     * Revoke every provider token for the subject.
     */
    public function destroyAll(Request $request, RevokeAllApiTokensAction $action): JsonResponse
    {
        $count = $action->execute($this->subject($request));

        return response()->json(['data' => ['count' => $count], 'code' => 'api_tokens_revoked', 'message' => 'API tokens were revoked.']);
    }

    /**
     * Serialize provider-neutral token metadata.
     *
     * @return array<string, mixed>
     */
    private function snapshot(ApiTokenSnapshot $token): array
    {
        return [
            'id' => $token->id,
            'name' => $token->name,
            'abilities' => $token->abilities,
            'last_used_at' => $token->lastUsedAt?->toIso8601String(),
            'expires_at' => $token->expiresAt?->toIso8601String(),
            'created_at' => $token->createdAt->toIso8601String(),
        ];
    }
}
