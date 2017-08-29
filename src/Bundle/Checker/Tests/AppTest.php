<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\Checker\Tests;

use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ClaimCheckerManagerFactory;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use PHPUnit\Framework\TestCase;

/**
 * @group CheckerBundle
 */
final class AppTest extends TestCase
{
    /**
     * @var AppKernel
     */
    private $customKernel;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->customKernel = new AppKernel('test', true);
        $this->customKernel->boot();
    }

    public function testHeaderCheckerManagerFactoryIsAvailable()
    {
        $this->assertInstanceOf(
            HeaderCheckerManagerFactory::class,
            $this->customKernel->getContainer()->get(HeaderCheckerManagerFactory::class)
        );
    }

    public function testHeaderCheckerManagerFactoryHasExpectedAliases()
    {
        $this->assertEquals(
            ['exp', 'iat', 'nbf'],
            $this->customKernel->getContainer()->get(HeaderCheckerManagerFactory::class)->aliases()
        );
    }

    public function testHeaderCheckerManagerCreation()
    {
        $this->assertInstanceOf(
            HeaderCheckerManager::class,
            $this->customKernel->getContainer()->get(HeaderCheckerManagerFactory::class)->create(['iat', 'nbf'])
        );
    }

    public function testClaimCheckerManagerFactoryIsAvailable()
    {
        $this->assertInstanceOf(
            ClaimCheckerManagerFactory::class,
            $this->customKernel->getContainer()->get(ClaimCheckerManagerFactory::class)
        );
    }

    public function testClaimCheckerManagerFactoryHasExpectedAliases()
    {
        $this->assertEquals(
            ['exp', 'iat', 'nbf'],
            $this->customKernel->getContainer()->get(ClaimCheckerManagerFactory::class)->aliases()
        );
    }

    public function testClaimCheckerManagerCreation()
    {
        $this->assertInstanceOf(
            ClaimCheckerManager::class,
            $this->customKernel->getContainer()->get(ClaimCheckerManagerFactory::class)->create(['iat', 'nbf'])
        );
    }
}
