<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Account;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nvl\Auth\Services\AuthTokens;
use Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations\ApiTokenData;

/**
 * Handles Sanctum-backed personal API token transport.
 */
final class ApiTokenController extends AuthenticatedController
{
    /**
     * List subject-owned provider tokens.
     */
    public function index(Request $request, AuthTokens $action): JsonResponse
    {
        $tokens = array_map($this->snapshot(...), $action->all($this->subject($request)));

        return response()->json(['data' => $tokens, 'code' => 'api_tokens_listed', 'message' => trans('nvl-auth::responsecode.api_tokens_listed')]);
    }

    /**
     * Issue one provider token.
     */
    public function store(ApiTokenData $data, Request $request, AuthTokens $action): JsonResponse
    {
        $issued = $action->create($this->subject($request), get_object_vars($data));

        return response()->json(['data' => [...$this->snapshot($issued->token), 'plain_text_token' => $issued->plainTextToken], 'code' => 'api_token_issued', 'message' => trans('nvl-auth::responsecode.api_token_issued')], 201);
    }

    /**
     * Update one provider token.
     */
    public function update(ApiTokenData $data, Request $request, string $tokenId, AuthTokens $action): JsonResponse
    {
        $token = $action->update($this->subject($request), $tokenId, get_object_vars($data));

        return response()->json(['data' => $this->snapshot($token), 'code' => 'api_token_updated', 'message' => trans('nvl-auth::responsecode.api_token_updated')]);
    }

    /**
     * Rotate one provider token.
     */
    public function rotate(ApiTokenData $data, Request $request, string $tokenId, AuthTokens $action): JsonResponse
    {
        $issued = $action->rotate($this->subject($request), $tokenId, get_object_vars($data));

        return response()->json(['data' => [...$this->snapshot($issued->token), 'plain_text_token' => $issued->plainTextToken], 'code' => 'api_token_rotated', 'message' => trans('nvl-auth::responsecode.api_token_rotated')]);
    }

    /**
     * Revoke one provider token.
     */
    public function destroy(Request $request, string $tokenId, AuthTokens $action): JsonResponse
    {
        $action->revoke($this->subject($request), $tokenId);

        return response()->json(['data' => null, 'code' => 'api_token_revoked', 'message' => trans('nvl-auth::responsecode.api_token_revoked')]);
    }

    /**
     * Revoke every provider token for the subject.
     */
    public function destroyAll(Request $request, AuthTokens $action): JsonResponse
    {
        $count = $action->revokeAll($this->subject($request));

        return response()->json(['data' => ['count' => $count], 'code' => 'api_tokens_revoked', 'message' => trans('nvl-auth::responsecode.api_tokens_revoked')]);
    }

    /**
     * Serialize provider-neutral token metadata.
     *
     * @return array<string, mixed>
     */
    private function snapshot(array $token): array
    {
        $data = ['id' => $token['id'], 'name' => $token['name'], 'abilities' => $token['abilities'], 'last_used_at' => $token['lastUsedAt']?->toIso8601String(), 'expires_at' => $token['expiresAt']?->toIso8601String(), 'created_at' => $token['createdAt']->toIso8601String()];

        return $data;
    }
}
