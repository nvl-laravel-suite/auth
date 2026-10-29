<?php

declare(strict_types=1);

return ['routes' => [
    'enabled' => env('NVL_AUTH_ROUTES_ENABLED', false),
    'prefix' => env('NVL_AUTH_ROUTES_PREFIX', 'nvl/api/v1/auth'),
    'middleware' => ['api'],
    'public' => ['enabled' => false, 'middleware' => ['throttle:nvl.auth.public']],
    'account' => ['enabled' => false, 'middleware' => ['auth', 'throttle:nvl.auth.account']],
    'management' => ['enabled' => false, 'middleware' => ['auth', 'throttle:nvl.auth.management']],
]];
