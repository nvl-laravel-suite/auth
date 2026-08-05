<?php

declare(strict_types=1);

namespace Nvl\Auth\Exceptions;

use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use RuntimeException;
use Throwable;

/**
 * Represents a stable package failure suitable for PHP and HTTP consumers.
 */
final class AuthException extends RuntimeException
{
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
        return new self('invalid_configuration', $message, 500);
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

        return new self(
            'feature_unavailable',
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
