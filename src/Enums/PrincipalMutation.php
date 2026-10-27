<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/**
 * Native operations that may map host principal extensions.
 *
 * @api
 */
enum PrincipalMutation: string
{
    case Registration = 'registration';
    case InvitationRegistration = 'invitation_registration';
    case ManagementCreate = 'management_create';
    case ManagementUpdate = 'management_update';
    case Profile = 'profile';
}
