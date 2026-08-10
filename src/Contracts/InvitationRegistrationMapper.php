<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Models\Invitation;

/**
 * Maps validated invitation registration input to configured principal model attributes.
 */
interface InvitationRegistrationMapper
{
    /**
     * Return model-ready attributes, including any host-owned extension fields.
     *
     * @param  array<string, mixed>  $validated
     * @return array<string, mixed>
     */
    public function map(Invitation $invitation, array $validated): array;
}
