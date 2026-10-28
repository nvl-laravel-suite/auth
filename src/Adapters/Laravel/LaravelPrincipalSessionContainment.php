<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Laravel;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Contracts\SecurityTokenContainment;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\Models\RememberCredential;
use Nvl\Auth\Services\PrincipalSecurity;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Contains native tokens, remember credentials and managed browser authority.
 */
final readonly class LaravelPrincipalSessionContainment implements PrincipalSessionContainment
{
    /**
     * Create the Laravel session containment adapter.
     */
    public function __construct(
        private ConfigRepository $configuration,
        private ApiTokenManager $tokens,
        private PrincipalSecurity $security,
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

        $principal->getConnection()->transaction(function () use ($principal): void {
            $this->security->lock($principal);
            if ($this->configuration->get('nvl-auth.features.managed_sessions.enabled') === true) {
                $sessions = new BrowserSession;
                if ($sessions->getConnection() !== $principal->getConnection()) {
                    throw AuthException::invalidConfiguration('Managed session containment requires one source.');
                }
                $reference = SubjectReference::fromAuthenticatable($principal);
                $sessions->newQuery()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNull('revoked_at')->update(['revoked_at' => now()]);
                RememberCredential::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNull('revoked_at')->update(['revoked_at' => now()]);
            }
            if (method_exists($principal, 'tokens') && ! (new \ReflectionMethod($principal, 'tokens'))->invoke($principal) instanceof MorphMany) {
                throw AuthException::invalidConfiguration('Session containment requires a Sanctum token relationship.');
            }
            if ($this->configuration->get('nvl-auth.features.api_tokens.enabled') === true) {
                $tokens = $this->tokens;
                if (! $tokens instanceof SecurityTokenContainment || $tokens->connection($principal) !== $principal->getConnection()) {
                    throw AuthException::invalidConfiguration('Account containment requires same-source SecurityTokenContainment.');
                }
                $tokens->revokeForSecurity($principal);
            }

            $rememberTokenName = $principal->getRememberTokenName();

            if ($rememberTokenName !== '') {
                $principal->setRememberToken(Str::random(60));
                $principal->saveQuietly();
            }

        });
        // Laravel expiry/GC owns physical payload cleanup; native revision/registry owns denial.
    }
}
