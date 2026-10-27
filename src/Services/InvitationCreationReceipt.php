<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;

/**
 * Records canonical Eloquent creations during one invitation resolver invocation.
 * Forwards events without adding listeners to shared or wrapped dispatchers.
 *
 * @internal
 */
final class InvitationCreationReceipt implements Dispatcher
{
    /** @var array<string, true> */
    private array $identifiers = [];

    public function __construct(private readonly Dispatcher $dispatcher, private readonly Model $prototype) {}

    /** Determine whether this invocation observed creation of the canonical returned row. */
    public function contains(Model $model): bool
    {
        $key = $model->getKey();

        return $model::class === $this->prototype::class
            && $model->getConnection() === $this->prototype->getConnection()
            && $model->getTable() === $this->prototype->getTable()
            && (is_string($key) || is_int($key)) && isset($this->identifiers[(string) $key]);
    }

    /** @return array<array-key, mixed>|null */
    public function dispatch(mixed $event, mixed $payload = [], mixed $halt = false): mixed
    {
        $result = $this->dispatcher->dispatch($event, $payload, $halt);
        $model = $payload instanceof Model ? $payload : (is_array($payload) ? ($payload[0] ?? null) : null);
        if ($event === 'eloquent.created: '.$this->prototype::class && $model instanceof Model
            && $model::class === $this->prototype::class && $model->getConnection() === $this->prototype->getConnection()
            && $model->getTable() === $this->prototype->getTable()) {
            $key = $model->getKey();
            if (is_string($key) || is_int($key)) {
                $this->identifiers[(string) $key] = true;
            }
        }

        return $result;
    }

    /** @param \Closure|string|array<array-key, mixed> $events
     * @param  \Closure|string|array<array-key, mixed>|null  $listener
     */
    public function listen(mixed $events, mixed $listener = null): void
    {
        $this->dispatcher->listen($events, $listener);
    }

    /** {@inheritDoc} */
    public function hasListeners(mixed $eventName): bool
    {
        return $this->dispatcher->hasListeners($eventName);
    }

    /** {@inheritDoc} */
    public function subscribe(mixed $subscriber): void
    {
        $this->dispatcher->subscribe($subscriber);
    }

    /** {@inheritDoc} */
    public function until(mixed $event, mixed $payload = []): mixed
    {
        return $this->dispatcher->until($event, $payload);
    }

    /** @param string $event
     * @param  array<array-key, mixed>  $payload
     */
    public function push(mixed $event, mixed $payload = []): void
    {
        $this->dispatcher->push($event, $payload);
    }

    /** {@inheritDoc} */
    public function flush(mixed $event): void
    {
        $this->dispatcher->flush($event);
    }

    /** {@inheritDoc} */
    public function forget(mixed $event): void
    {
        $this->dispatcher->forget($event);
    }

    /** {@inheritDoc} */
    public function forgetPushed(): void
    {
        $this->dispatcher->forgetPushed();
    }
}
