<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Algorithm\JWAInterface;
use Jose\Algorithm\JWAManager;
use Jose\Algorithm\Signature\ES384;
use Jose\Factory\AlgorithmManagerFactory;
use Jose\Test\BaseTestCase;

/**
 * Class JWAManagerTest.
 *
 * @group JWA
 * @group Unit
 */
class JWAManagerBaseTest extends BaseTestCase
{
    public function testAlgorithmIsSupported()
    {
        $jwa_manager = AlgorithmManagerFactory::createAlgorithmManager(['ES256', 'ES384']);

        self::assertTrue($jwa_manager->isAlgorithmSupported('ES256'));
        self::assertTrue($jwa_manager->isAlgorithmSupported('ES384'));

        self::assertFalse($jwa_manager->isAlgorithmSupported('ES512'));
        self::assertFalse($jwa_manager->isAlgorithmSupported('HS384'));

        self::assertEquals(['ES256', 'ES384'], $jwa_manager->listAlgorithms());
        self::assertInstanceOf(JWAInterface::class, $jwa_manager->getAlgorithm('ES256'));
        self::assertInstanceOf(JWAInterface::class, $jwa_manager->getAlgorithms()['ES256']);

        $jwa_manager->removeAlgorithm('ES256');
        $jwa_manager->removeAlgorithm('ES256');

        self::assertNull($jwa_manager->getAlgorithm('ES256'));
        self::assertEquals(['ES384'], $jwa_manager->listAlgorithms());

        $jwa_manager->removeAlgorithm(new ES384());

        self::assertNull($jwa_manager->getAlgorithm('HS384'));
        self::assertEquals([], $jwa_manager->listAlgorithms());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Argument must be a string or a JWAInterface object.
     */
    public function testBadArgument()
    {
        $jwa_manager = new JWAManager();
        $jwa_manager->removeAlgorithm(new \stdClass());
    }

    public function testAllAlgorithms()
    {
        $algorithms = [
            'HS256',
            'HS384',
            'HS512',
            'ES256',
            'ES384',
            'ES512',
            'RS256',
            'RS384',
            'RS512',
            'PS256',
            'PS384',
            'PS512',
            'dir',
            'RSA1_5',
            'RSA-OAEP',
            'RSA-OAEP-256',
            'ECDH-ES',
            'ECDH-ES+A128KW',
            'ECDH-ES+A192KW',
            'ECDH-ES+A256KW',
            'A128KW',
            'A192KW',
            'A256KW',
            'A128GCMKW',
            'A192GCMKW',
            'A256GCMKW',
            'PBES2-HS256+A128KW',
            'PBES2-HS384+A192KW',
            'PBES2-HS512+A256KW',
            'A128CBC-HS256',
            'A192CBC-HS384',
            'A256CBC-HS512',
            'A128GCM',
            'A192GCM',
            'A256GCM',
        ];
        $jwa_manager = AlgorithmManagerFactory::createAlgorithmManager($algorithms);

        self::assertEquals($algorithms, $jwa_manager->listAlgorithms());
    }
}
