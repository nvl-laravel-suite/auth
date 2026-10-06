<?php

declare(strict_types=1);

use Nvl\Auth\Tests\Fixtures\MembershipBindingScenario;

it('replaces only the native fallback with explicit Tenancy in both provider orders', function (bool $resolved, string $order): void {
    MembershipBindingScenario::assertNativeOverride($this->app, $resolved, $order);
})->with([[false, 'tenancy first'], [true, 'tenancy first'], [false, 'auth first'], [true, 'auth first']]);
