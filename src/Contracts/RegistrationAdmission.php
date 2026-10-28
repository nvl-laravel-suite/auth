<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Enums\RegistrationMethod;

/**
 * Applies additional host signup policy after native mode and input validation.
 *
 * @api
 */
interface RegistrationAdmission
{
    /**
     * Called inside the source write transaction; no external effects.
     *
     * @param  array<string, mixed>  $validatedExtensions  Validated physical host fields.
     */
    public function assertAllowed(RegistrationMethod $method, string $normalizedEmail, array $validatedExtensions): void;
}
