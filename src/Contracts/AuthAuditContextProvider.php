<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

/**
 * Supplies optional transport context for package audit facts.
 */
interface AuthAuditContextProvider
{
    /**
     * Return the current request IP address when available.
     */
    public function ipAddress(): ?string;

    /**
     * Return the current request user agent when available.
     */
    public function userAgent(): ?string;

    /**
     * Return the current correlation identifier when available.
     */
    public function requestId(): ?string;
}
