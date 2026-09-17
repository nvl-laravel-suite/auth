<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Laravel;

use Illuminate\Http\Request;
use Nvl\Auth\Contracts\BrowserSession;
use Nvl\Auth\Contracts\TenantAuthenticationSession;
use Nvl\Auth\Exceptions\AuthException;

/**
 * Applies browser-session operations through Laravel's current request.
 */
final readonly class LaravelBrowserSession implements BrowserSession, TenantAuthenticationSession
{
    private const string TENANT_FLOW_BINDINGS = 'nvl-auth.tenant-flow-bindings';

    private const string TENANT_FLOW_INTENTS = 'nvl-auth.tenant-flow-intents';

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
}
