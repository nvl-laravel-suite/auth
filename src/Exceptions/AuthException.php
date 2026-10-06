<?php

declare(strict_types=1);

namespace Nvl\Auth\Exceptions;

use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthResponseCode;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Support\Contracts\RespondableException;
use Nvl\Support\Exceptions\ExceptionResponse;
use Nvl\Support\Traits\InteractsWithPackageFailure;
use RuntimeException;
use Throwable;

/**
 * @api
 * Represents a stable package failure suitable for PHP and HTTP consumers.
 */
final class AuthException extends RuntimeException implements RespondableException
{
    use InteractsWithPackageFailure;

    /** Preserve the explicit legacy machine code supplied by the consumer. */
    public function responseCode(): string
    {
        return $this->errorCode;
    }

    /** Resolve enum-backed presentation or a safe legacy fallback. */
    protected function exceptionResponse(): ExceptionResponse
    {
        return new ExceptionResponse('auth', AuthResponseCode::tryFrom($this->errorCode) ?? AuthResponseCode::OperationFailed, $this->status, $this->context);
    }

    /**
     * Create a new failure using a declared package code.
     *
     * @param  array<string, mixed>  $context
     */
    public static function because(AuthResponseCode $code, string $diagnosticMessage, int $status = 422, array $context = [], ?Throwable $previous = null): self
    {
        return new self($code->value, $diagnosticMessage, $status, $context, $previous);
    }

    /**
     * Create an authentication package exception.
     *
     * @param  array<string, mixed>  $context
     */
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly int $status = 422,
        public readonly array $context = [],
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    /**
     * Create an invalid package configuration failure.
     */
    public static function invalidConfiguration(string $message): self
    {
        return self::because(AuthResponseCode::InvalidConfiguration, $message, 500);
    }

    /**
     * Create a neutral unavailable-feature failure.
     *
     * @param  list<string>  $dependencies
     */
    public static function featureUnavailable(
        AuthFeature|string $feature,
        FeatureOperation|string $operation,
        array $dependencies = [],
    ): self {
        $featureValue = $feature instanceof AuthFeature ? $feature->value : $feature;
        $operationValue = $operation instanceof FeatureOperation ? $operation->value : $operation;

        return self::because(
            AuthResponseCode::FeatureUnavailable,
            'The requested authentication capability is unavailable.',
            404,
            [
                'feature' => $featureValue,
                'operation' => $operationValue,
                'dependencies' => $dependencies,
            ],
        );
    }
}
