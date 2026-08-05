<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Laravel;

use Illuminate\Http\Request;
use Nvl\Auth\Contracts\AuthAuditContextProvider;

/**
 * Reads optional audit context from Laravel's current request.
 */
final readonly class LaravelRequestAuditContextProvider implements AuthAuditContextProvider
{
    /**
     * Create the request audit-context adapter.
     */
    public function __construct(private Request $request) {}

    /** {@inheritDoc} */
    public function ipAddress(): ?string
    {
        return $this->request->ip();
    }

    /** {@inheritDoc} */
    public function userAgent(): ?string
    {
        return $this->request->userAgent();
    }

    /** {@inheritDoc} */
    public function requestId(): ?string
    {
        return $this->request->headers->get('X-Request-ID');
    }
}
