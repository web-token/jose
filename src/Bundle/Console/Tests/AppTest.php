<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\Console\Tests;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * @group ConsoleBundle
 */
final class AppTest extends TestCase
{
    /**
     * @var AppKernel
     */
    private $customKernel;

    /**
     * @var Application
     */
    private $application;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->customKernel = new AppKernel('test', true);
        $this->customKernel->boot();

        $this->application = new Application($this->customKernel);
    }

    public function testECKeyCreationCommand()
    {
        $command = $this->application->find('key:generate:ec');
        $commandTester = new CommandTester($command);
        $commandTester->execute([
            '--curve' => 'P-256',
        ]);

        $output = $commandTester->getDisplay();
        $this->assertTrue(is_string($output), $output);

        $json = json_decode($output, true);
        $this->assertTrue(is_array($json));

        $jwk = JWK::create($json);
        $this->assertEquals('EC', $jwk->get('kty'));
        $this->assertEquals('P-256', $jwk->get('crv'));
    }

    public function testRSAKeysetCreationCommand()
    {
        $command = $this->application->find('keyset:generate:rsa');
        $commandTester = new CommandTester($command);
        $commandTester->execute([
            '--quantity' => 2,
            '--size' => 1024,
        ]);

        $output = $commandTester->getDisplay();
        $this->assertTrue(is_string($output), $output);

        $json = json_decode($output, true);
        $this->assertTrue(is_array($json));

        $jwkset = JWKSet::createFromKeyData($json);
        $this->assertEquals(2, count($jwkset));
    }
}
