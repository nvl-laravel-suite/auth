<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Laravel;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Nvl\Auth\Contracts\BrowserSession;
use Nvl\Auth\Contracts\TenantAuthenticationSession;
use Nvl\Auth\Enums\TenantAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\PendingTenantAuthenticationIntent;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\ValueObjects\TenantId;
use Throwable;

/**
 * Applies browser-session operations through Laravel's current request.
 */
final readonly class LaravelBrowserSession implements BrowserSession, TenantAuthenticationSession
{
    private const string TENANT_FLOW_BINDINGS = 'nvl-auth.tenant-flow-bindings';

    private const string TENANT_FLOW_INTENTS = 'nvl-auth.tenant-flow-intents';

    private const int MAXIMUM_PENDING_TENANT_AUTHENTICATION_INTENTS = 8;

    private const string PENDING_TENANT_AUTHENTICATION_INTENTS = 'nvl-auth.pending-tenant-authentication-intents';

    /**
     * Create the Laravel browser-session adapter.
     */
    public function __construct(private Request $request) {}

    /** {@inheritDoc} */
    public function regenerateIdentifier(): void
    {
        if ($this->request->hasSession()) {
            $this->request->session()->regenerate();
        }
    }

    /** {@inheritDoc} */
    public function invalidate(): void
    {
        if ($this->request->hasSession()) {
            $this->request->session()->invalidate();
        }
    }

    /** {@inheritDoc} */
    public function regenerateCsrfToken(): void
    {
        if ($this->request->hasSession()) {
            $this->request->session()->regenerateToken();
        }
    }

    /** {@inheritDoc} */
    public function confirmPassword(): bool
    {
        if (! $this->request->hasSession()) {
            return false;
        }

        $this->request->session()->passwordConfirmed();

        return true;
    }

    /** Return a server-generated per-flow binding preserved across session ID rotation. */
    public function authenticationFlowBinding(string $flow): string
    {
        if (! $this->request->hasSession() || trim($flow) === '' || mb_strlen($flow) > 160) {
            throw new AuthException(
                'authentication_flow_unavailable',
                'The authentication flow is unavailable.',
                400,
            );
        }
        $key = hash('sha256', $flow);
        $bindings = $this->request->session()->get(self::TENANT_FLOW_BINDINGS, []);
        $bindings = is_array($bindings) ? $bindings : [];
        $binding = $bindings[$key] ?? null;
        if (! is_string($binding) || $binding === '') {
            $binding = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
            $bindings[$key] = $binding;
            $this->request->session()->put(self::TENANT_FLOW_BINDINGS, $bindings);
        }

        return $binding;
    }

    /** Remove a consumed flow binding without changing other browser-tab flows. */
    public function forgetAuthenticationFlowBinding(string $flow): void
    {
        if (! $this->request->hasSession()) {
            return;
        }
        $bindings = $this->request->session()->get(self::TENANT_FLOW_BINDINGS, []);
        if (is_array($bindings)) {
            unset($bindings[hash('sha256', $flow)]);
            $this->request->session()->put(self::TENANT_FLOW_BINDINGS, $bindings);
        }
    }

    /** Store an opaque intent nonce server-side for one exact provider flow. */
    public function storeAuthenticationIntent(string $flow, string $nonce): void
    {
        $this->authenticationFlowBinding($flow);
        $intents = $this->request->session()->get(self::TENANT_FLOW_INTENTS, []);
        $intents = is_array($intents) ? $intents : [];
        $intents[hash('sha256', $flow)] = $nonce;
        $this->request->session()->put(self::TENANT_FLOW_INTENTS, $intents);
    }

    /** Pull the one-use nonce without exposing any sibling browser-tab flow. */
    public function pullAuthenticationIntent(string $flow): ?string
    {
        if (! $this->request->hasSession()) {
            return null;
        }
        $key = hash('sha256', $flow);
        $intents = $this->request->session()->get(self::TENANT_FLOW_INTENTS, []);
        if (! is_array($intents) || ! is_string($intents[$key] ?? null)) {
            return null;
        }
        $nonce = $intents[$key];
        unset($intents[$key]);
        $this->request->session()->put(self::TENANT_FLOW_INTENTS, $intents);

        return $nonce;
    }

    /** Store one exact pending tenant intent without exposing it to the client. */
    public function storePendingTenantAuthenticationIntent(PendingTenantAuthenticationIntent $intent): void
    {
        if (! $this->request->hasSession()) {
            throw new AuthException('authentication_flow_unavailable', 'The authentication flow is unavailable.', 400);
        }

        $pending = $this->pendingTenantAuthenticationIntents();
        if (! $intent->expiresAt->isFuture()) {
            $this->persistPendingTenantAuthenticationIntents($pending);

            return;
        }
        $pending[$this->pendingKey($intent)] = $intent;
        uksort($pending, static function (string $left, string $right) use ($pending): int {
            $expiry = $pending[$left]->expiresAt->getTimestamp() <=> $pending[$right]->expiresAt->getTimestamp();

            return $expiry !== 0 ? $expiry : strcmp($left, $right);
        });
        while (count($pending) > self::MAXIMUM_PENDING_TENANT_AUTHENTICATION_INTENTS) {
            $oldest = array_key_first($pending);
            unset($pending[$oldest]);
        }
        $this->persistPendingTenantAuthenticationIntents($pending);
    }

    /** Select one unambiguous pending intent using only trusted tenant and subject state. */
    public function pendingTenantAuthenticationIntent(
        TenantId $tenant,
        SubjectReference $subject,
    ): ?PendingTenantAuthenticationIntent {
        $matches = array_values(array_filter(
            $this->pendingTenantAuthenticationIntents(),
            static fn (PendingTenantAuthenticationIntent $intent): bool => $intent->tenant->value === $tenant->value
                && $intent->subject->type === $subject->type
                && $intent->subject->identifier === $subject->identifier,
        ));
        if (count($matches) > 1) {
            throw new AuthException(
                'tenant_authentication_intent_ambiguous',
                'More than one tenant authentication intent matches this session.',
                409,
            );
        }

        return $matches[0] ?? null;
    }

    /** Forget only the selected pending reference after successful consumption. */
    public function forgetPendingTenantAuthenticationIntent(PendingTenantAuthenticationIntent $intent): void
    {
        if (! $this->request->hasSession()) {
            return;
        }
        $pending = $this->pendingTenantAuthenticationIntents();
        unset($pending[$this->pendingKey($intent)]);
        $this->persistPendingTenantAuthenticationIntents($pending);
    }

    /** @return array<string, PendingTenantAuthenticationIntent> */
    private function pendingTenantAuthenticationIntents(): array
    {
        if (! $this->request->hasSession()) {
            return [];
        }
        $stored = $this->request->session()->get(self::PENDING_TENANT_AUTHENTICATION_INTENTS, []);
        if (! is_array($stored)) {
            throw new AuthException('tenant_authentication_intent_invalid', 'The tenant authentication intent is invalid.', 410);
        }

        $pending = [];
        foreach ($stored as $key => $state) {
            if (! is_string($key) || ! is_array($state)) {
                throw new AuthException('tenant_authentication_intent_invalid', 'The tenant authentication intent is invalid.', 410);
            }
            $intent = $this->hydratePendingTenantAuthenticationIntent($state);
            if ($intent->expiresAt->isFuture()) {
                $pending[$key] = $intent;
            }
        }
        if (count($pending) !== count($stored)) {
            $this->persistPendingTenantAuthenticationIntents($pending);
        }

        return $pending;
    }

    /** @param array<array-key, mixed> $state */
    private function hydratePendingTenantAuthenticationIntent(array $state): PendingTenantAuthenticationIntent
    {
        try {
            $purpose = is_string($state['purpose'] ?? null)
                ? TenantAuthenticationPurpose::tryFrom($state['purpose'])
                : null;
            $provider = $state['provider'] ?? null;
            if (! is_string($state['subject_type'] ?? null)
                || ! is_string($state['subject_id'] ?? null)
                || ! is_string($state['nonce'] ?? null)
                || ! is_string($state['session_binding'] ?? null)
                || ! $purpose instanceof TenantAuthenticationPurpose
                || ($provider !== null && ! is_string($provider))
                || ! is_bool($state['subject_bound'] ?? null)
                || ! is_string($state['tenant_id'] ?? null)
                || ! is_string($state['expires_at'] ?? null)) {
                throw new AuthException('tenant_authentication_intent_invalid', 'The tenant authentication intent is invalid.', 410);
            }

            return new PendingTenantAuthenticationIntent(
                new SubjectReference($state['subject_type'], $state['subject_id']),
                $state['nonce'],
                $state['session_binding'],
                $purpose,
                $provider,
                $state['subject_bound'],
                new TenantId($state['tenant_id']),
                CarbonImmutable::parse($state['expires_at']),
            );
        } catch (AuthException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw new AuthException('tenant_authentication_intent_invalid', 'The tenant authentication intent is invalid.', 410);
        }
    }

    private function pendingKey(PendingTenantAuthenticationIntent $intent): string
    {
        return hash('sha256', $intent->sessionBinding."\0".$intent->nonce);
    }

    /** @param array<string, PendingTenantAuthenticationIntent> $pending */
    private function persistPendingTenantAuthenticationIntents(array $pending): void
    {
        $stored = [];
        foreach ($pending as $key => $intent) {
            $stored[$key] = [
                'subject_type' => $intent->subject->type,
                'subject_id' => $intent->subject->identifier,
                'nonce' => $intent->nonce,
                'session_binding' => $intent->sessionBinding,
                'purpose' => $intent->purpose->value,
                'provider' => $intent->provider,
                'subject_bound' => $intent->subjectBound,
                'tenant_id' => $intent->tenant->value,
                'expires_at' => $intent->expiresAt->toIso8601String(),
            ];
        }
        $this->request->session()->put(self::PENDING_TENANT_AUTHENTICATION_INTENTS, $stored);
    }
}
