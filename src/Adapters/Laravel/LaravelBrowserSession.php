<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Laravel;

use Illuminate\Http\Request;
use Nvl\Auth\Contracts\BrowserSession;

/**
 * Applies browser-session operations through Laravel's current request.
 */
final readonly class LaravelBrowserSession implements BrowserSession
{
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
}
