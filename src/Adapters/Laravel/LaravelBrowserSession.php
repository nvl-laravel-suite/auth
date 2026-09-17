<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Laravel;

use Illuminate\Http\Request;
use Nvl\Auth\Contracts\BrowserSession;
use Nvl\Auth\Contracts\TenantAuthenticationSession;
use Nvl\Auth\Enums\TenantAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\PendingTenantAuthenticationIntent;
use Nvl\Auth\ValueObjects\SubjectReference;
use Throwable;

/**
 * Applies browser-session operations through Laravel's current request.
 */
final readonly class LaravelBrowserSession implements BrowserSession, TenantAuthenticationSession
{
    private const string TENANT_FLOW_BINDINGS = 'nvl-auth.tenant-flow-bindings';

    private const string TENANT_FLOW_INTENTS = 'nvl-auth.tenant-flow-intents';

    private const string PENDING_TENANT_AUTHENTICATION_INTENT = 'nvl-auth.pending-tenant-authentication-intent';

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

        $this->request->session()->put(self::PENDING_TENANT_AUTHENTICATION_INTENT, [
            'subject_type' => $intent->subject->type,
            'subject_id' => $intent->subject->identifier,
            'nonce' => $intent->nonce,
            'session_binding' => $intent->sessionBinding,
            'purpose' => $intent->purpose->value,
            'provider' => $intent->provider,
            'subject_bound' => $intent->subjectBound,
        ]);
    }

    /** Read the pending intent without consuming it before tenant validation succeeds. */
    public function pendingTenantAuthenticationIntent(): ?PendingTenantAuthenticationIntent
    {
        if (! $this->request->hasSession()) {
            return null;
        }
        $state = $this->request->session()->get(self::PENDING_TENANT_AUTHENTICATION_INTENT);
        if ($state === null) {
            return null;
        }
        if (! is_array($state)) {
            throw new AuthException('tenant_authentication_intent_invalid', 'The tenant authentication intent is invalid.', 410);
        }

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
                || ! is_bool($state['subject_bound'] ?? null)) {
                throw new AuthException('tenant_authentication_intent_invalid', 'The tenant authentication intent is invalid.', 410);
            }

            return new PendingTenantAuthenticationIntent(
                new SubjectReference($state['subject_type'], $state['subject_id']),
                $state['nonce'],
                $state['session_binding'],
                $purpose,
                $provider,
                $state['subject_bound'],
            );
        } catch (AuthException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw new AuthException('tenant_authentication_intent_invalid', 'The tenant authentication intent is invalid.', 410);
        }
    }

    /** Forget the pending reference only after successful intent consumption. */
    public function forgetPendingTenantAuthenticationIntent(): void
    {
        if ($this->request->hasSession()) {
            $this->request->session()->forget(self::PENDING_TENANT_AUTHENTICATION_INTENT);
        }
    }
}
