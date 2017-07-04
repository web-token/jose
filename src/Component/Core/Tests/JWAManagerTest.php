<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Tests;

use Jose\Component\Core\JWAInterface;
use Jose\Component\Core\JWAManager;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\RS256;
use PHPUnit\Framework\TestCase;

/**
 * final class JWKTest.
 *
 * @group Unit
 * @group JWAManager
 */
final class JWAManagerTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The array must contains JWAInterface objects.
     */
    public function testCreateManagerWithBadList()
    {
        JWAManager::create(['foo']);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The algorithm "HS384" is not supported.
     */
    public function testCreateManagerAndRetrieveAlgorithm()
    {
        $manager = JWAManager::create([new HS512(), new RS256()]);

        $this->assertEquals(['HS512', 'RS256'], $manager->list());
        $this->assertTrue($manager->has('HS512'));
        $this->assertFalse($manager->has('HS384'));
        $this->assertInstanceOf(JWAInterface::class, $manager->get('HS512'));
        $manager->get('HS384');
    }
}
