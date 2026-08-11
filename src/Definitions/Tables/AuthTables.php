<?php

declare(strict_types=1);

namespace Nvl\Auth\Definitions\Tables;

/**
 * Defines the canonical table names owned by the Auth package.
 */
final class AuthTables
{
    public const string Users = 'nvl_auth_users';

    public const string Roles = 'nvl_auth_roles';

    public const string Permissions = 'nvl_auth_permissions';

    public const string ModelHasPermissions = 'nvl_auth_model_has_permissions';

    public const string ModelHasRoles = 'nvl_auth_model_has_roles';

    public const string RoleHasPermissions = 'nvl_auth_role_has_permissions';

    public const string PersonalAccessTokens = 'nvl_auth_personal_access_tokens';

    public const string PasswordResetTokens = 'nvl_auth_password_reset_tokens';

    public const string Clients = 'nvl_auth_clients';

    public const string ClientSessions = 'nvl_auth_client_sessions';

    public const string Invitations = 'nvl_auth_invitations';

    public const string Challenges = 'nvl_auth_challenges';

    public const string TotpCredentials = 'nvl_auth_totp_credentials';

    public const string Passkeys = 'nvl_auth_passkeys';

    public const string RecoveryCodes = 'nvl_auth_recovery_codes';

    public const string SocialIdentities = 'nvl_auth_social_identities';

    public const string Audits = 'nvl_auth_audits';

    private function __construct() {}
}
