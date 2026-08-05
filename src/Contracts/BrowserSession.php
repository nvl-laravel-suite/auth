<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

/**
 * Adapts the current browser session without coupling Actions to HTTP.
 */
interface BrowserSession
{
    /**
     * Rotate the current session identifier after authentication.
     */
    public function regenerateIdentifier(): void;

    /**
     * Invalidate the current session during logout.
     */
    public function invalidate(): void;

    /**
     * Rotate the current session's CSRF token.
     */
    public function regenerateCsrfToken(): void;

    /**
     * Mark the current session as password-confirmed.
     *
     * @return bool Whether an active session was available.
     */
    public function confirmPassword(): bool;
}
