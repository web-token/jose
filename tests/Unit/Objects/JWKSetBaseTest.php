<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Factory\JWKFactory;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSetInterface;
use Jose\Test\BaseTestCase;

/**
 * Class JWKTest.
 *
 * @group Unit
 * @group JWKSet
 */
class JWKSetBaseTest extends BaseTestCase
{
    public function testKeySelection()
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('enc');
        self::assertInstanceOf(JWKInterface::class, $jwk);
    }

    public function testKeySelectionWithAlgorithm()
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('sig', 'RS256');
        self::assertInstanceOf(JWKInterface::class, $jwk);
        self::assertEquals([
                'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'n' => 'vnMTRCMvsS04M1yaKR112aB8RxOkWHFixZO68wCRlVLxK4ugckXVD_Ebcq-kms1T2XpoWntVfBuX40r2GvcD9UsTFt_MZlgd1xyGwGV6U_tfQUll5mKxCPjr60h83LXKJ_zmLXIqkV8tAoIg78a5VRWoms_0Bn09DKT3-RBWFjk=',
                'e' => 'AQAB',
            ],
            $jwk->getAll()
        );
    }

    public function testKeySelectionWithAlgorithmAndKeyId()
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('sig', 'RS256', ['kid' => '02491f945c951adf156f370788e8ccdabf8877a8']);
        self::assertInstanceOf(JWKInterface::class, $jwk);
        self::assertEquals([
                'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'n' => 'rI67uHIDWDgCy_Ut-FhhjTCkEcqzoO80IRgdpk_fJHlDmXhMTJKPizxbIEMs0wRHRZpwH-4D20thpnQB5Mgx6-XM9kOvcYpHSdcYME77BwX6uQG-hw2w77NOhYiCSZCLzx-5ld5Wjy0dympL-ExqQw-wrWipMX7NQhIbJqVbZ18=',
                'e' => 'AQAB',
            ],
            $jwk->getAll()
        );
    }

    public function testKeySelectionWithKeyId()
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('sig', null, ['kid' => '02491f945c951adf156f370788e8ccdabf8877a8']);
        self::assertInstanceOf(JWKInterface::class, $jwk);
        self::assertEquals([
                'kid' => '02491f945c951adf156f370788e8ccdabf8877a8',
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'n' => 'rI67uHIDWDgCy_Ut-FhhjTCkEcqzoO80IRgdpk_fJHlDmXhMTJKPizxbIEMs0wRHRZpwH-4D20thpnQB5Mgx6-XM9kOvcYpHSdcYME77BwX6uQG-hw2w77NOhYiCSZCLzx-5ld5Wjy0dympL-ExqQw-wrWipMX7NQhIbJqVbZ18=',
                'e' => 'AQAB',
            ],
            $jwk->getAll()
        );
    }

    public function testKeySelectionReturnsNothing()
    {
        $jwkset = $this->getPublicKeySet();

        $jwk = $jwkset->selectKey('enc', null, ['kid' => '02491f945c951adf156f370788e8ccdabf8877a8']);
        self::assertNull($jwk);
    }

    public function testCreateKeySetFromValues()
    {
        $values = ['keys' => [[
            'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
            'kty' => 'RSA',
            'alg' => 'RS256',
            'use' => 'sig',
            'n' => 'vnMTRCMvsS04M1yaKR112aB8RxOkWHFixZO68wCRlVLxK4ugckXVD_Ebcq-kms1T2XpoWntVfBuX40r2GvcD9UsTFt_MZlgd1xyGwGV6U_tfQUll5mKxCPjr60h83LXKJ_zmLXIqkV8tAoIg78a5VRWoms_0Bn09DKT3-RBWFjk=',
            'e' => 'AQAB',
        ]]];
        $jwkset = JWKFactory::createFromValues($values);
        self::assertInstanceOf(JWKSetInterface::class, $jwkset);
        self::assertEquals(1, $jwkset->countKeys());
        self::assertTrue(isset($jwkset[0]));
        self::assertFalse(isset($jwkset[1]));
        self::assertEquals($values['keys'][0], $jwkset[0]->getAll());
    }
}
