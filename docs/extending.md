# Extending

Bind narrow contracts in `src/Contracts` for identity resolution, eligibility, management/system access, audit and optional engines. Inject native service families for operations. Consumer subclasses opt into optional Permission/Sanctum traits. Never use ambient request state as authority. See [PHP API](php-api.md).

For Socialite, register a scoped `SocialIdentityProviderFactory` before the Auth provider. Construct a fresh SDK driver from the current request in every `make` call; see the [factory example](../README.md). The default factory denies acquisition until configured.
