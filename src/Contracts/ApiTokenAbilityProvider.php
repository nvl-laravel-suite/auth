<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Supplies the API-token abilities a host subject may request.
 */
interface ApiTokenAbilityProvider
{
    /**
     * Return allowlisted ability handles for a subject.
     *
     * @return list<string>
     */
    public function abilities(Authenticatable $subject): array;
}
