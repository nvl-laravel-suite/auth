<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\ModelNotFoundException;
use Nvl\Auth\Services\AuthRoles;
use Nvl\Auth\Services\RbacEntityLocator;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;

it('rejects foreign tenant role identifiers and restores context after exceptions', function (): void {
    $scenario = new AuthTenancyScenario;
    $actor = $this->user('rbac-lifecycle@example.test');
    $reference = SubjectReference::fromAuthenticatable($actor);
    $scenario->member($scenario->a(), $reference, true);
    $scenario->member($scenario->b(), $reference, true);
    $foreign = $scenario->run($scenario->b(), fn () => app(AuthRoles::class)->create($actor, ['name' => 'foreign']));

    $scenario->run($scenario->a(), function () use ($foreign, $scenario): void {
        expect(fn () => app(RbacEntityLocator::class)->role($foreign->id))
            ->toThrow(ModelNotFoundException::class);
        $scenario->run($scenario->b(), fn () => expect(app(RbacEntityLocator::class)->role($foreign->id)->id)->toBe($foreign->id));
        expect(fn () => app(RbacEntityLocator::class)->role($foreign->id))
            ->toThrow(ModelNotFoundException::class);
    });
});
