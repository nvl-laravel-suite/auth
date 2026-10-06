<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Spatie\Permission\PermissionRegistrar;
use WeakReference;

/** Carries an existing registrar without retaining scoped readiness or model state. */
final class PermissionRegistrarReference
{
    /** @var WeakReference<PermissionRegistrar>|null */
    private ?WeakReference $reference = null;

    /** Remember the native registrar without extending its lifetime. */
    public function remember(PermissionRegistrar $registrar): void
    {
        $this->reference = WeakReference::create($registrar);
    }

    /** Return the still-live native registrar, if one has been resolved. */
    public function current(): ?PermissionRegistrar
    {
        return $this->reference?->get();
    }
}
