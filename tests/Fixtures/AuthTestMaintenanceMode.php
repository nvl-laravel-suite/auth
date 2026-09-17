<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Contracts\Foundation\MaintenanceMode;

/** Holds isolated in-memory maintenance state for Auth tenancy tests. */
final class AuthTestMaintenanceMode implements MaintenanceMode
{
    private bool $enabled = true;

    /** @var array<string, mixed> */
    private array $payload = [];

    /** @param array<string, mixed> $payload */
    public function activate(array $payload): void
    {
        $this->enabled = true;
        $this->payload = array_slice($payload, 0, 20, true);
    }

    /** End fixture maintenance. */
    public function deactivate(): void
    {
        $this->enabled = false;
        $this->payload = [];
    }

    /** Report whether fixture maintenance is active. */
    public function active(): bool
    {
        return $this->enabled;
    }

    /** @return array<string, mixed> */
    public function data(): array
    {
        return $this->payload;
    }
}
