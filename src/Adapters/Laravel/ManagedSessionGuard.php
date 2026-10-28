<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Laravel;

use Carbon\CarbonImmutable;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthRememberCredentials;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Symfony\Component\HttpFoundation\Request;

/** Explicit Laravel driver; the standard Laravel recaller path is disabled. @api */
final class ManagedSessionGuard extends SessionGuard
{
    private ?AuthRememberCredentials $rememberCredentials = null;

    private ?AuthenticationSessions $nativeSessions = null;

    private bool $managedRecallAttempted = false;

    /** Driver construction only; does not select or replace any host guard. @internal */
    public function configureNative(AuthRememberCredentials $remember, AuthenticationSessions $sessions): void
    {
        $this->rememberCredentials = $remember;
        $this->nativeSessions = $sessions;
    }

    public function user(): ?Authenticatable
    {
        $subject = parent::user();
        if ($subject !== null || $this->loggedOut || $this->managedRecallAttempted) {
            return $subject;
        }
        $this->managedRecallAttempted = true;
        $cookie = $this->request->cookies->get($this->getRecallerName());
        if (! is_string($cookie) || $cookie === '') {
            return null;
        }
        try {
            self::assertCookieConfiguration();
            $plain = app(Encrypter::class)->decrypt($cookie, false);
            if (! is_string($plain)) {
                throw new AuthException('remember_credential_invalid', 'The remembered credential is unavailable.', 401);
            }
            $parts = explode('.', $plain, 2);
            if (count($parts) !== 2 || $this->rememberCredentials === null || $this->nativeSessions === null) {
                throw new AuthException('remember_credential_invalid', 'The remembered credential is unavailable.', 401);
            }
            $context = new AuthenticationRequestContext(guardName: $this->name, sessionBinding: $this->session->getId());
            $proof = $this->rememberCredentials->resume($parts[0], $parts[1], $this->name, $context);
            $subject = $this->nativeSessions->establishFromProof($proof->reveal(), $this, $this->session, $context, true);
            $this->viaRemember = true;

            return $subject;
        } catch (\Throwable $exception) {
            $this->forgetManagedCookie();
            if ($exception instanceof AuthException && $exception->errorCode === 'second_factor_required') {
                return null;
            }
            if ($exception instanceof DecryptException || $exception instanceof AuthException) {
                return null;
            }
            throw $exception;
        }
    }

    public function setRequest(Request $request): static
    {
        if ($this->request !== $request) {
            $this->managedRecallAttempted = false;
            $this->recallAttempted = false;
            $this->loggedOut = false;
            $this->viaRemember = false;
            $this->user = null;
        }
        parent::setRequest($request);

        return $this;
    }

    /** Guard login never creates a standard, globally reusable recaller. */
    public function login(Authenticatable $user, $remember = false): void
    {
        parent::login($user, false);
    }

    protected function recaller(): null
    {
        return null;
    }

    public function logout(): void
    {
        parent::logout();
        $this->forgetManagedCookie();
    }

    public function getRecallerName(): string
    {
        return 'nvl_auth_remember_'.hash('sha256', $this->name);
    }

    public static function assertCookieConfiguration(): void
    {
        if (config('session.secure') !== true || config('session.http_only', true) !== true || ! in_array(config('session.same_site', 'lax'), ['lax', 'strict', 'none'], true)) {
            throw AuthException::invalidConfiguration('Managed remember cookies require Secure, HttpOnly and an explicit SameSite policy.');
        }
    }

    /** Queue only after native assurance and enrollment; ciphertext also protects transports without EncryptCookies. @internal */
    public function queueManagedCookie(string $selector, #[\SensitiveParameter] string $secret, CarbonImmutable $expiresAt): void
    {
        self::assertCookieConfiguration();
        $value = app(Encrypter::class)->encrypt($selector.'.'.$secret, false);
        $minutes = max(1, (int) ceil(CarbonImmutable::now('UTC')->diffInSeconds($expiresAt, false) / 60));
        $jar = $this->getCookieJar();
        $options = $this->cookieOptions();
        $jar->queue($jar->make($this->getRecallerName(), $value, $minutes, $options['path'], $options['domain'], true, true, false, $options['sameSite']));
    }

    private function forgetManagedCookie(): void
    {
        $options = $this->cookieOptions();
        $jar = $this->getCookieJar();
        $jar->unqueue($this->getRecallerName());
        $jar->queue($jar->forget($this->getRecallerName(), $options['path'], $options['domain']));
    }

    /** @return array{path: string, domain: ?string, sameSite: string} */
    private function cookieOptions(): array
    {
        $path = config('session.path', '/');
        $domain = config('session.domain');
        $sameSite = config('session.same_site', 'lax');
        if (! is_string($path) || $domain !== null && ! is_string($domain) || ! is_string($sameSite)) {
            throw AuthException::invalidConfiguration('Invalid managed cookie scope.');
        }

        return ['path' => $path, 'domain' => $domain, 'sameSite' => $sameSite];
    }

    /** @return array{guard: string, authenticated: bool} */
    public function __debugInfo(): array
    {
        return ['guard' => $this->name, 'authenticated' => $this->user !== null];
    }
}
