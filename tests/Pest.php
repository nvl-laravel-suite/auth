<?php

declare(strict_types=1);

use Nvl\Auth\Tests\DisabledAuthProviderTestCase;
use Nvl\Auth\Tests\TestCase;

uses(TestCase::class)->in('Feature', 'Unit');
uses(DisabledAuthProviderTestCase::class)->in('Provider');
