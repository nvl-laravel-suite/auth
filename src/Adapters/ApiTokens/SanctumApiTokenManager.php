<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\ApiTokens;

use Carbon\CarbonImmutable;
use DateTimeInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Support\Facades\DB;
use Laravel\Sanctum\Contracts\HasApiTokens as HasApiTokensContract;
use Laravel\Sanctum\HasApiTokens;
use Laravel\Sanctum\NewAccessToken;
use Laravel\Sanctum\PersonalAccessToken;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\OwnerBoundApiTokenManager;
use Nvl\Auth\Contracts\TransactionalApiTokenManager;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Results\IssuedApiToken;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Support\Ownership\Contracts\OwnershipBoundary;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/**
 * Manages personal access tokens directly in Sanctum's authoritative table.
 */
final class SanctumApiTokenManager implements ApiTokenManager, OwnerBoundApiTokenManager, TransactionalApiTokenManager
{
    /**
     * Create the namespaced Sanctum adapter.
     */
    public function __construct(private readonly AuthConfiguration $configuration, private readonly OwnershipBoundary $boundary) {}

    /** {@inheritDoc} */
    public function connection(Authenticatable $subject): Connection
    {
        return $this->tokens($this->subject($subject))->getModel()->getConnection();
    }

    /**
     * List subject-owned Sanctum tokens.
     *
     * @return list<array{id: string, name: string, abilities: list<string>, lastUsedAt: CarbonImmutable|null, expiresAt: CarbonImmutable|null, createdAt: CarbonImmutable}>
     */
    public function list(Authenticatable $subject): array
    {
        $model = $this->subject($subject);

        return array_values($this->managedTokens($model)->get()->map(fn (PersonalAccessToken $token): array => $this->snapshot($token))->sortByDesc(static fn (array $token): int => $token['createdAt']->getTimestamp())->all());
    }

    /**
     * Issue one Sanctum token.
     *
     * @param  array{name: string, abilities: list<string>, expiresAt: CarbonImmutable|null}  $data
     */
    public function create(Authenticatable $subject, array $data): IssuedApiToken
    {
        $model = $this->subject($subject);
        $connection = $this->tokens($model)->getModel()->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($data, $model): IssuedApiToken {
            $created = $this->createToken($model, $data);
            $created->accessToken->forceFill($this->boundary->attributes('auth.tokens'))->save();

            return new IssuedApiToken($this->snapshot($created->accessToken->refresh()), $created->plainTextToken);
        }, 3);
    }

    /**
     * Update one subject-owned Sanctum token.
     *
     * @param  array{name: string, abilities: list<string>, expiresAt: CarbonImmutable|null}  $data
     * @return array{id: string, name: string, abilities: list<string>, lastUsedAt: CarbonImmutable|null, expiresAt: CarbonImmutable|null, createdAt: CarbonImmutable}
     */
    public function update(Authenticatable $subject, string $tokenId, array $data): array
    {
        $model = $this->subject($subject);
        $connection = $this->tokens($model)->getModel()->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($data, $model, $tokenId): array {
            $token = $this->token($model, $tokenId, true);
            $token->forceFill(['name' => $this->managedName($data['name']), 'abilities' => $data['abilities'], 'expires_at' => $data['expiresAt']])->save();

            return $this->snapshot($token->refresh());
        }, 3);
    }

    /**
     * Issue the replacement before deleting the old token in one connection transaction.
     *
     * @param  array{name: string, abilities: list<string>, expiresAt: CarbonImmutable|null}  $data
     */
    public function rotate(Authenticatable $subject, string $tokenId, array $data): IssuedApiToken
    {
        $model = $this->subject($subject);
        $connection = $this->tokens($model)->getModel()->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($data, $model, $subject, $tokenId): IssuedApiToken {
            $oldToken = $this->token($model, $tokenId, true);
            $issued = $this->create($subject, $data);
            $oldToken->delete();

            return $issued;
        }, 3);
    }

    /**
     * Revoke one subject-owned Sanctum token.
     */
    public function revoke(Authenticatable $subject, string $tokenId): bool
    {
        $model = $this->subject($subject);

        return $this->managedTokens($model)->whereKey($tokenId)->delete() > 0;
    }

    /**
     * Revoke every subject-owned Sanctum token.
     */
    public function revokeAll(Authenticatable $subject): int
    {
        $deleted = $this->managedTokens($this->subject($subject))->delete();
        if (! is_int($deleted)) {
            throw AuthException::invalidConfiguration('Sanctum returned an invalid revoked-token count.');
        }

        return $deleted;
    }

    /** Resolve only a live persisted subject-owned token; an ambient scope never supplies its owner. */
    public function ownerForToken(Authenticatable $subject, string $tokenId): ?OwnerReference
    {
        $model = $this->subject($subject);
        $token = $this->tokens($model)->getModel();
        $row = $token->getConnection()->table($token->getTable())->useWritePdo()->where($token->getKeyName(), $tokenId)->where('tokenable_type', $model->getMorphClass())->where('tokenable_id', $model->getKey())->whereRaw('name LIKE ?', [$this->namespace().':%'])->first();
        if ($row === null || ! is_string($row->owner_reference ?? null) || $row->expires_at !== null && (! is_string($row->expires_at) || CarbonImmutable::parse($row->expires_at)->isPast())) {
            return null;
        }
        $reference = OwnerReference::fromJson($row->owner_reference);

        return $row->owner_scope_key === $reference->scopeKey() ? $reference : null;
    }

    /**
     * Require a Sanctum-capable Eloquent subject.
     */
    private function subject(Authenticatable $subject): Model
    {
        if (! class_exists(PersonalAccessToken::class)) {
            throw AuthException::invalidConfiguration('API tokens require laravel/sanctum.');
        }
        if (! $subject instanceof Model || ! $subject instanceof HasApiTokensContract && ! in_array(HasApiTokens::class, class_uses_recursive($subject), true)) {
            throw AuthException::invalidConfiguration('The host authenticatable must use Sanctum HasApiTokens.');
        }

        return $subject;
    }

    /**
     * Resolve one subject-owned token.
     */
    private function token(Model $subject, string $tokenId, bool $lock = false): PersonalAccessToken
    {
        $query = $this->managedTokens($subject)->whereKey($tokenId);
        if ($lock) {
            $query->lockForUpdate();
        }
        $token = $query->first();
        if (! $token instanceof PersonalAccessToken) {
            throw new AuthException('api_token_unavailable', 'The API token is unavailable.', 404);
        }

        return $token;
    }

    /**
     * Resolve Sanctum's morph-many relationship for contract- or trait-based hosts.
     *
     * @return MorphMany<PersonalAccessToken, Model>
     */
    private function tokens(Model $subject): MorphMany
    {
        $method = new \ReflectionMethod($subject, 'tokens');
        $tokens = $method->invoke($subject);
        if (! $tokens instanceof MorphMany) {
            throw AuthException::invalidConfiguration('Sanctum HasApiTokens returned an invalid token relationship.');
        }

        return $tokens;
    }

    /**
     * Restrict the Sanctum relationship to package-managed tokens.
     *
     * @return Builder<PersonalAccessToken>
     */
    private function managedTokens(Model $subject): Builder
    {
        $query = $this->tokens($subject)->whereRaw('name LIKE ?', [$this->namespace().':%'])->getQuery();

        return $this->boundary->query($query, 'auth.tokens');
    }

    /**
     * Invoke Sanctum token issuance for contract- or trait-based hosts.
     *
     * @param  array{name: string, abilities: list<string>, expiresAt: CarbonImmutable|null}  $data
     */
    private function createToken(Model $subject, array $data): NewAccessToken
    {
        $method = new \ReflectionMethod($subject, 'createToken');
        $created = $method->invoke($subject, $this->managedName($data['name']), $data['abilities'], $data['expiresAt']);
        if (! $created instanceof NewAccessToken) {
            throw AuthException::invalidConfiguration('Sanctum HasApiTokens returned an invalid issued token.');
        }

        return $created;
    }

    /**
     * Convert Sanctum metadata into the package's provider-neutral snapshot.
     *
     * @return array{id: string, name: string, abilities: list<string>, lastUsedAt: CarbonImmutable|null, expiresAt: CarbonImmutable|null, createdAt: CarbonImmutable}
     */
    private function snapshot(PersonalAccessToken $token): array
    {
        $createdAt = $this->date($token->getAttribute('created_at'));
        if (! $createdAt instanceof CarbonImmutable) {
            throw AuthException::invalidConfiguration('Sanctum token timestamps are unavailable.');
        }
        $rawAbilities = $token->getAttribute('abilities');
        $abilities = is_array($rawAbilities) ? array_values(array_filter($rawAbilities, 'is_string')) : [];
        $identifier = $token->getKey();
        $name = $token->getAttribute('name');
        if (! is_string($identifier) && ! is_int($identifier) || ! is_string($name) || ! str_starts_with($name, $this->namespace().':')) {
            throw AuthException::invalidConfiguration('Sanctum token identity metadata is unavailable.');
        }

        return ['id' => (string) $identifier, 'name' => substr($name, strlen($this->namespace()) + 1), 'abilities' => $abilities, 'lastUsedAt' => $this->date($token->getAttribute('last_used_at')), 'expiresAt' => $this->date($token->getAttribute('expires_at')), 'createdAt' => $createdAt];
    }

    /**
     * Normalize one optional provider timestamp.
     */
    private function date(mixed $value): ?CarbonImmutable
    {
        return $value instanceof DateTimeInterface ? CarbonImmutable::instance($value) : null;
    }

    /**
     * Return the validated package ownership namespace.
     */
    private function namespace(): string
    {
        $namespace = $this->configuration->string('features.api_tokens.settings.namespace', 'nvl-auth');
        if (preg_match('/\A[a-z0-9][a-z0-9_.-]{0,39}\z/', $namespace) !== 1) {
            throw AuthException::invalidConfiguration('Auth API-token namespace must be a lowercase identifier no longer than 40 characters.');
        }

        return $namespace;
    }

    /**
     * Prefix one public token name with the package ownership marker.
     */
    private function managedName(string $name): string
    {
        return $this->namespace().':'.$name;
    }
}
