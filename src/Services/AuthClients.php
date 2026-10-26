<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use InvalidArgumentException;
use JsonException;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthClient;
use Nvl\Auth\Models\AuthClientSession;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Complete native AuthClients operations.
 *
 * @api
 */
final readonly class AuthClients
{
    /** Native Auth operation. */
    public function __construct(private FeatureGate $features, private ManagementAuthorizer $authorization, private AuthAuditRecorder $audits, private SecretHasher $hasher, private AuthPipeline $pipeline) {}

    /**
     * Persist a new Auth client.
     *
     * @param  array<string, mixed>  $data
     */
    public function create(Authenticatable $actor, array $data): AuthClient
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Issue);
        $data = $this->validateStoreClient($data);
        $this->authorization->authorize($actor, 'nvl.auth.clients.create');
        $connection = (new AuthClient)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($actor, $data): AuthClient {
            $client = AuthClient::query()->create(['name' => $data['name'], 'surface' => $data['surface'], 'base_url' => rtrim($data['baseUrl'], '/'), 'return_paths' => $data['returnPaths'], 'allowed_origins' => $data['allowedOrigins'], 'allowed_flows' => $data['allowedFlows'], 'metadata' => $data['metadata'], 'is_active' => $data['active']]);
            $this->audits->record('client.created', actor: $actor, clientId: $client->identifier(), metadata: ['surface' => $client->surface]);

            return $client;
        }, 3);
    }

    /**
     * Delete a client and its correlation rows.
     */
    public function delete(Authenticatable $actor, AuthClient $client): void
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Revoke);
        $this->authorization->authorize($actor, 'nvl.auth.clients.delete', $client);
        DB::connection($client->getConnectionName())->transaction(function () use ($actor, $client): void {
            $clientId = $client->identifier();
            $this->audits->record('client.deleted', actor: $actor, clientId: $clientId, metadata: ['client_id' => $clientId]);
            AuthClient::query()->whereKey($clientId)->delete();
        }, 3);
    }

    /**
     * End one client-session record idempotently.
     */
    public function endSession(AuthClientSession $session, string $reason = 'logout'): AuthClientSession
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Revoke);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Revoke);
        $reason = trim($reason);
        if ($reason === '' || mb_strlen($reason) > 64 || preg_match('/[\x00-\x1F\x7F]/', $reason) === 1) {
            throw new AuthException('client_session_reason_invalid', 'The client session end reason is invalid.', 422);
        }

        return DB::connection($session->getConnectionName())->transaction(function () use ($reason, $session): AuthClientSession {
            /** @var AuthClientSession $locked */
            $locked = AuthClientSession::query()->whereKey($session->identifier())->lockForUpdate()->firstOrFail();
            if ($locked->ended_at === null) {
                $locked->forceFill(['ended_at' => CarbonImmutable::now('UTC'), 'end_reason' => $reason])->save();
                $subject = $locked->subject_type !== null && $locked->subject_id !== null ? new SubjectReference($locked->subject_type, $locked->subject_id) : null;
                $this->audits->record('client.session_ended', subject: $subject, clientId: $locked->client_id, metadata: ['client_session_id' => $locked->identifier(), 'reason' => $reason]);
            }

            return $locked;
        }, 3);
    }

    /**
     * Return a bounded client page.
     *
     * @return LengthAwarePaginator<int, AuthClient>
     */
    public function paginate(Authenticatable $actor, int $perPage = 25): LengthAwarePaginator
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.clients.viewAny');

        return AuthClient::query()->latest()->paginate(max(1, min($perPage, 100)));
    }

    /**
     * Create or refresh one client-session correlation record.
     *
     * @param  array<string, mixed>  $metadata
     */
    public function recordSession(AuthClient $client, string $sessionId, ?Authenticatable $subject = null, ?string $ipAddress = null, ?string $userAgent = null, array $metadata = []): AuthClientSession
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Issue);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        if (trim($sessionId) === '' || mb_strlen($sessionId) > 255 || preg_match('/[\x00-\x1F\x7F]/', $sessionId) === 1 || $ipAddress !== null && mb_strlen($ipAddress) > 64 || $userAgent !== null && mb_strlen($userAgent) > 1024) {
            throw new AuthException('client_session_input_invalid', 'The client session input is invalid.', 422);
        }
        try {
            $encodedMetadata = json_encode($metadata, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new AuthException('client_session_input_invalid', 'The client session metadata is invalid.', 422, previous: $exception);
        }
        if (strlen($encodedMetadata) > 32768) {
            throw new AuthException('client_session_input_invalid', 'The client session metadata is too large.', 422);
        }
        $reference = $subject instanceof Authenticatable ? SubjectReference::fromAuthenticatable($subject) : null;
        $hash = $this->hasher->hash('client-session', $sessionId);
        try {
            return DB::connection($client->getConnectionName())->transaction(function () use ($client, $hash, $ipAddress, $metadata, $reference, $subject, $userAgent): AuthClientSession {
                /** @var AuthClient|null $lockedClient */
                $lockedClient = AuthClient::query()->whereKey($client->identifier())->lockForUpdate()->first();
                if (! $lockedClient instanceof AuthClient || ! $lockedClient->is_active) {
                    throw new AuthException('client_unavailable', 'The authentication client is unavailable.', 404);
                }
                /** @var AuthClientSession|null $session */
                $session = AuthClientSession::query()->where('client_id', $lockedClient->identifier())->where('session_id_hash', $hash)->lockForUpdate()->first();
                if ($session instanceof AuthClientSession && $session->ended_at !== null) {
                    throw new AuthException('client_session_ended', 'The client session has ended.', 409);
                }
                $session ??= new AuthClientSession(['client_id' => $lockedClient->identifier(), 'session_id_hash' => $hash]);
                $session->fill(['subject_type' => $reference?->type, 'subject_id' => $reference?->identifier, 'ip_address' => $ipAddress, 'user_agent' => $userAgent, 'metadata' => $metadata, 'authenticated_at' => $reference === null ? null : CarbonImmutable::now('UTC'), 'last_seen_at' => CarbonImmutable::now('UTC')])->save();
                $this->audits->record('client.session_recorded', subject: $reference, actor: $subject, clientId: $lockedClient->identifier(), metadata: ['client_session_id' => $session->identifier()]);

                return $session;
            }, 3);
        } catch (QueryException $exception) {
            if (in_array($exception->errorInfo[0] ?? null, ['23000', '23505'], true) && (str_contains($exception->getMessage(), 'nvl_auth_client_sessions_client_hash_unique') || str_contains($exception->getMessage(), 'auth_client_sessions.client_id'))) {
                throw new AuthException('client_session_conflict', 'The client session is already being recorded.', 409, previous: $exception);
            }
            throw $exception;
        }
    }

    /**
     * Set the client state atomically and idempotently.
     */
    public function setActive(Authenticatable $actor, AuthClient $client, bool $active): AuthClient
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl.auth.clients.update', $client);

        return DB::connection($client->getConnectionName())->transaction(function () use ($active, $actor, $client): AuthClient {
            /** @var AuthClient $locked */
            $locked = AuthClient::query()->lockForUpdate()->findOrFail($client->identifier());
            if ($locked->is_active !== $active) {
                $locked->forceFill(['is_active' => $active])->save();
                $this->audits->record($active ? 'client.activated' : 'client.deactivated', actor: $actor, clientId: $locked->identifier());
            }

            return $locked;
        }, 3);
    }

    /**
     * Authorize and return one route-resolved client.
     */
    public function find(Authenticatable $actor, AuthClient $client): AuthClient
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl.auth.clients.view', $client);

        return $client;
    }

    /**
     * Resolve an allowlisted return target for an active client.
     *
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     */
    public function start(array $data): array
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Use);
        $data = $this->validateStartClientAuth($data);
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);

        return $this->pipeline->run('client_started', new AuthPipelineContext('client_started', ['client_id' => $data['clientId'], 'flow' => $data['flow']]), function () use ($data): array {
            /** @var AuthClient|null $client */
            $client = AuthClient::query()->whereKey($data['clientId'])->where('is_active', true)->first();
            if (! $client instanceof AuthClient) {
                throw new AuthException('client_unavailable', 'The authentication client is unavailable.', 404);
            }
            $flows = is_array($client->allowed_flows) ? $client->allowed_flows : [];
            $paths = is_array($client->return_paths) ? $client->return_paths : [];
            $origins = is_array($client->allowed_origins) ? $client->allowed_origins : [];
            if (! in_array($data['flow'], $flows, true) || ! in_array($data['returnPath'], $paths, true)) {
                throw new AuthException('client_redirect_invalid', 'The client flow or return target is not allowlisted.', 422);
            }
            if ($origins !== [] && $data['origin'] === null || $data['origin'] !== null && ! in_array($data['origin'], $origins, true)) {
                throw new AuthException('client_origin_invalid', 'The client origin is not allowlisted.', 422);
            }
            DB::connection($client->getConnectionName())->transaction(function () use ($client, $data): void {
                AuthClient::query()->whereKey($client->identifier())->update(['last_used_at' => CarbonImmutable::now('UTC')]);
                $this->audits->record('client.started', clientId: $client->identifier(), metadata: ['flow' => $data['flow']]);
            }, 3);

            return ['client' => $client, 'flow' => $data['flow'], 'returnUrl' => rtrim($client->base_url, '/').$data['returnPath']];
        });
    }

    /**
     * Touch one active correlation by its host session identifier.
     */
    public function touchSession(string $clientId, string $sessionId): AuthClientSession
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Update);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        if (trim($sessionId) === '' || mb_strlen($sessionId) > 255 || preg_match('/[\x00-\x1F\x7F]/', $sessionId) === 1) {
            throw new AuthException('client_session_input_invalid', 'The client session input is invalid.', 422);
        }
        $connection = (new AuthClientSession)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($clientId, $sessionId): AuthClientSession {
            /** @var AuthClientSession|null $session */
            $session = AuthClientSession::query()->where('client_id', $clientId)->where('session_id_hash', $this->hasher->hash('client-session', $sessionId))->whereNull('ended_at')->lockForUpdate()->first();
            if (! $session instanceof AuthClientSession) {
                throw new AuthException('client_session_unavailable', 'The client session is unavailable.', 404);
            }
            $session->forceFill(['last_seen_at' => CarbonImmutable::now('UTC')])->save();

            return $session;
        }, 3);
    }

    /**
     * Update a client atomically.
     *
     * @param  array<string, mixed>  $data
     */
    public function update(Authenticatable $actor, AuthClient $client, array $data): AuthClient
    {
        $this->features->assertAllowed(AuthFeature::Clients, FeatureOperation::Update);
        $data = $this->validateUpdateClient($data);
        $this->authorization->authorize($actor, 'nvl.auth.clients.update', $client);

        return DB::connection($client->getConnectionName())->transaction(function () use ($actor, $client, $data): AuthClient {
            /** @var AuthClient $locked */
            $locked = AuthClient::query()->lockForUpdate()->findOrFail($client->identifier());
            $locked->fill(['name' => $data['name'], 'surface' => $data['surface'], 'base_url' => rtrim($data['baseUrl'], '/'), 'return_paths' => $data['returnPaths'], 'allowed_origins' => $data['allowedOrigins'], 'allowed_flows' => $data['allowedFlows'], 'metadata' => $data['metadata'], 'is_active' => $data['active']])->save();
            $this->audits->record('client.updated', actor: $actor, clientId: $locked->identifier());

            return $locked;
        }, 3);
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{clientId: string, flow: string, returnPath: string, origin: string|null}
     */
    private function validateStartClientAuth(array $data): array
    {
        if (array_diff(array_keys($data), ['clientId', 'flow', 'returnPath', 'origin']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['clientId'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [clientId].');
        }
        if (! is_string($data['flow'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [flow].');
        }
        if (! is_string($data['returnPath'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [returnPath].');
        }
        if (! array_key_exists('origin', $data)) {
            $data['origin'] = null;
        }
        if (! ($data['origin'] === null || is_string($data['origin']))) {
            throw new InvalidArgumentException('Invalid Auth input [origin].');
        }
        Validator::make($data, ['clientId' => ['required', 'string', 'max:191'], 'flow' => ['required', 'string'], 'returnPath' => ['required', 'string']])->validate();

        return $data;
    }

    /** Native Auth operation. */
    private static function validateStoreClientValidHttpUrl(string $url, bool $originOnly): bool
    {
        if (mb_strlen($url) > 2048 || filter_var($url, FILTER_VALIDATE_URL) === false) {
            return false;
        }
        $parts = parse_url($url);
        if (! is_array($parts) || ! isset($parts['scheme'], $parts['host']) || ! in_array(mb_strtolower((string) $parts['scheme']), ['http', 'https'], true) || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            return false;
        }

        return ! $originOnly || ! isset($parts['path']) || $parts['path'] === '' || $parts['path'] === '/';
    }

    /** Native Auth operation. */
    private static function validateStoreClientValidReturnPath(mixed $path): bool
    {
        return is_string($path) && mb_strlen($path) <= 2048 && str_starts_with($path, '/') && ! str_starts_with($path, '//') && preg_match('/[\x00-\x1F\x7F\\\\]/', $path) !== 1;
    }

    /** Native Auth operation. */
    private static function validateStoreClientValidOrigin(mixed $origin): bool
    {
        return is_string($origin) && self::validateStoreClientValidHttpUrl($origin, true);
    }

    /** Native Auth operation. */
    private static function validateStoreClientValidFlow(mixed $flow): bool
    {
        return is_string($flow) && preg_match('/\A[a-z][a-z0-9_.-]{0,79}\z/', $flow) === 1;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{name: string, surface: string, baseUrl: string, returnPaths: array<array-key, mixed>, allowedOrigins: array<array-key, mixed>, allowedFlows: array<array-key, mixed>, metadata: array<array-key, mixed>, active: bool}
     */
    private function validateStoreClient(array $data): array
    {
        if (array_diff(array_keys($data), ['name', 'surface', 'baseUrl', 'returnPaths', 'allowedOrigins', 'allowedFlows', 'metadata', 'active']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['name'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [name].');
        }
        if (! is_string($data['surface'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [surface].');
        }
        if (! is_string($data['baseUrl'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [baseUrl].');
        }
        if (! array_key_exists('returnPaths', $data)) {
            $data['returnPaths'] = [];
        }
        if (! is_array($data['returnPaths'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [returnPaths].');
        }
        if (! array_key_exists('allowedOrigins', $data)) {
            $data['allowedOrigins'] = [];
        }
        if (! is_array($data['allowedOrigins'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [allowedOrigins].');
        }
        if (! array_key_exists('allowedFlows', $data)) {
            $data['allowedFlows'] = ['login'];
        }
        if (! is_array($data['allowedFlows'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [allowedFlows].');
        }
        if (! array_key_exists('metadata', $data)) {
            $data['metadata'] = [];
        }
        if (! is_array($data['metadata'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [metadata].');
        }
        if (! array_key_exists('active', $data)) {
            $data['active'] = true;
        }
        if (! is_bool($data['active'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [active].');
        }
        if (trim($data['name']) === '' || mb_strlen($data['name']) > 120) {
            throw new InvalidArgumentException('Auth client names must contain between one and 120 characters.');
        }
        if (preg_match('/\A[a-z][a-z0-9_-]{0,39}\z/', $data['surface']) !== 1) {
            throw new InvalidArgumentException('Auth client surfaces must be lowercase identifiers.');
        }
        if (! self::validateStoreClientValidHttpUrl($data['baseUrl'], false)) {
            throw new InvalidArgumentException('Auth client base URLs must be absolute HTTP(S) URLs without credentials, query, or fragment.');
        }
        foreach ($data['returnPaths'] as $path) {
            if (! self::validateStoreClientValidReturnPath($path)) {
                throw new InvalidArgumentException('Auth client return paths must be absolute local paths.');
            }
        }
        foreach ($data['allowedOrigins'] as $origin) {
            if (! self::validateStoreClientValidOrigin($origin)) {
                throw new InvalidArgumentException('Auth client origins must be HTTP(S) origins without path, credentials, query, or fragment.');
            }
        }
        foreach ($data['allowedFlows'] as $flow) {
            if (! self::validateStoreClientValidFlow($flow)) {
                throw new InvalidArgumentException('Auth client flows must be lowercase identifiers.');
            }
        }
        $encodedMetadata = json_encode($data['metadata']);
        if (! is_string($encodedMetadata) || strlen($encodedMetadata) > 16384) {
            throw new InvalidArgumentException('Auth client metadata must be JSON-serializable and no larger than 16 KiB.');
        }

        return $data;
    }

    /** Native Auth operation. */
    private static function validateUpdateClientValidHttpUrl(string $url, bool $originOnly): bool
    {
        if (mb_strlen($url) > 2048 || filter_var($url, FILTER_VALIDATE_URL) === false) {
            return false;
        }
        $parts = parse_url($url);
        if (! is_array($parts) || ! isset($parts['scheme'], $parts['host']) || ! in_array(mb_strtolower((string) $parts['scheme']), ['http', 'https'], true) || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            return false;
        }

        return ! $originOnly || ! isset($parts['path']) || $parts['path'] === '' || $parts['path'] === '/';
    }

    /** Native Auth operation. */
    private static function validateUpdateClientValidReturnPath(mixed $path): bool
    {
        return is_string($path) && mb_strlen($path) <= 2048 && str_starts_with($path, '/') && ! str_starts_with($path, '//') && preg_match('/[\x00-\x1F\x7F\\\\]/', $path) !== 1;
    }

    /** Native Auth operation. */
    private static function validateUpdateClientValidOrigin(mixed $origin): bool
    {
        return is_string($origin) && self::validateUpdateClientValidHttpUrl($origin, true);
    }

    /** Native Auth operation. */
    private static function validateUpdateClientValidFlow(mixed $flow): bool
    {
        return is_string($flow) && preg_match('/\A[a-z][a-z0-9_.-]{0,79}\z/', $flow) === 1;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{name: string, surface: string, baseUrl: string, returnPaths: array<array-key, mixed>, allowedOrigins: array<array-key, mixed>, allowedFlows: array<array-key, mixed>, metadata: array<array-key, mixed>, active: bool}
     */
    private function validateUpdateClient(array $data): array
    {
        if (array_diff(array_keys($data), ['name', 'surface', 'baseUrl', 'returnPaths', 'allowedOrigins', 'allowedFlows', 'metadata', 'active']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['name'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [name].');
        }
        if (! is_string($data['surface'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [surface].');
        }
        if (! is_string($data['baseUrl'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [baseUrl].');
        }
        if (! array_key_exists('returnPaths', $data)) {
            $data['returnPaths'] = [];
        }
        if (! is_array($data['returnPaths'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [returnPaths].');
        }
        if (! array_key_exists('allowedOrigins', $data)) {
            $data['allowedOrigins'] = [];
        }
        if (! is_array($data['allowedOrigins'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [allowedOrigins].');
        }
        if (! array_key_exists('allowedFlows', $data)) {
            $data['allowedFlows'] = ['login'];
        }
        if (! is_array($data['allowedFlows'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [allowedFlows].');
        }
        if (! array_key_exists('metadata', $data)) {
            $data['metadata'] = [];
        }
        if (! is_array($data['metadata'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [metadata].');
        }
        if (! array_key_exists('active', $data)) {
            $data['active'] = true;
        }
        if (! is_bool($data['active'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [active].');
        }
        if (trim($data['name']) === '' || mb_strlen($data['name']) > 120) {
            throw new InvalidArgumentException('Auth client names must contain between one and 120 characters.');
        }
        if (preg_match('/\A[a-z][a-z0-9_-]{0,39}\z/', $data['surface']) !== 1) {
            throw new InvalidArgumentException('Auth client surfaces must be lowercase identifiers.');
        }
        if (! self::validateUpdateClientValidHttpUrl($data['baseUrl'], false)) {
            throw new InvalidArgumentException('Auth client base URLs must be absolute HTTP(S) URLs without credentials, query, or fragment.');
        }
        foreach ($data['returnPaths'] as $path) {
            if (! self::validateUpdateClientValidReturnPath($path)) {
                throw new InvalidArgumentException('Auth client return paths must be absolute local paths.');
            }
        }
        foreach ($data['allowedOrigins'] as $origin) {
            if (! self::validateUpdateClientValidOrigin($origin)) {
                throw new InvalidArgumentException('Auth client origins must be HTTP(S) origins without path, credentials, query, or fragment.');
            }
        }
        foreach ($data['allowedFlows'] as $flow) {
            if (! self::validateUpdateClientValidFlow($flow)) {
                throw new InvalidArgumentException('Auth client flows must be lowercase identifiers.');
            }
        }
        $encodedMetadata = json_encode($data['metadata']);
        if (! is_string($encodedMetadata) || strlen($encodedMetadata) > 16384) {
            throw new InvalidArgumentException('Auth client metadata must be JSON-serializable and no larger than 16 KiB.');
        }

        return $data;
    }
}
