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
use Jose\Test\BaseTestCase;

/**
 * @group OKPKeys
 * @group Unit
 */
class OKPKeysBaseTest extends BaseTestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unsupported "Ed455" curve
     */
    public function testCreateOKPKeyWithInvalidKeySize()
    {
        JWKFactory::createOKPKey(['crv' => 'Ed455']);
    }

    public function testCreateOKPKeyWithCurveX25519()
    {
        if (!function_exists('curve25519_public')) {
            $this->markTestSkipped('EdDSA extension not available');
        }

        $jwk = JWKFactory::createOKPKey(
            [
                'kid' => 'KEY',
                'crv' => 'X25519',
                'alg' => 'ECDH-ES',
                'use' => 'enc',
            ]
        );

        self::assertEquals('OKP', $jwk->get('kty'));
        self::assertTrue($jwk->has('x'));
        self::assertTrue($jwk->has('d'));
        self::assertEquals('KEY', $jwk->get('kid'));
        self::assertEquals('ECDH-ES', $jwk->get('alg'));
        self::assertEquals('enc', $jwk->get('use'));
    }

    public function testCreateOKPKeyWithCurveEd25519()
    {
        if (!function_exists('ed25519_publickey')) {
            $this->markTestSkipped('EdDSA extension not available');
        }

        $jwk = JWKFactory::createOKPKey(
            [
                'kid' => 'KEY',
                'crv' => 'Ed25519',
                'alg' => 'EdDSA',
                'use' => 'sig',
            ]
        );

        self::assertEquals('OKP', $jwk->get('kty'));
        self::assertTrue($jwk->has('x'));
        self::assertTrue($jwk->has('d'));
        self::assertEquals('KEY', $jwk->get('kid'));
        self::assertEquals('EdDSA', $jwk->get('alg'));
        self::assertEquals('sig', $jwk->get('use'));
    }
}
