<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Laravel;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Contains Sanctum tokens, remember credentials, and Laravel database sessions.
 */
final readonly class LaravelPrincipalSessionContainment implements PrincipalSessionContainment
{
    /**
     * Create the Laravel session containment adapter.
     */
    public function __construct(
        private ConfigRepository $configuration,
        private DatabaseManager $database,
    ) {}

    /**
     * Contain every built-in credential surface for one principal.
     */
    public function contain(
        Authenticatable $principal,
        string $operation,
        ?SystemMutationContext $context = null,
    ): void {
        if (! $principal instanceof Model) {
            throw AuthException::invalidConfiguration('Session containment requires an Eloquent principal.');
        }

        if (method_exists($principal, 'tokens')) {
            $principal->tokens()->delete();
        }

        $rememberTokenName = $principal->getRememberTokenName();

        if ($rememberTokenName !== '') {
            $principal->setRememberToken(Str::random(60));
            $principal->saveQuietly();
        }

        if ($this->configuration->get('session.driver') !== 'database') {
            return;
        }

        $table = $this->configuration->get('session.table', 'sessions');
        $connection = $this->configuration->get('session.connection');

        if (! is_string($table) || trim($table) === '') {
            throw AuthException::invalidConfiguration('Laravel database session containment requires a session table.');
        }

        $connection = is_string($connection) && trim($connection) !== '' ? trim($connection) : null;
        $identifier = $principal->getAuthIdentifier();

        if (! is_string($identifier) && ! is_int($identifier)) {
            throw AuthException::invalidConfiguration('Session containment requires a string-compatible principal identifier.');
        }

        $this->database->connection($connection)
            ->table(trim($table))
            ->where('user_id', (string) $identifier)
            ->delete();
    }
}
