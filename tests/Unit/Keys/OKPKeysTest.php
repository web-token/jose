<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Factory\JWKFactory;
use Jose\Test\TestCase;

/**
 * @group OKPKeys
 * @group Unit
 */
class OKPKeysTest extends TestCase
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

        $this->assertEquals('OKP', $jwk->get('kty'));
        $this->assertTrue($jwk->has('x'));
        $this->assertTrue($jwk->has('d'));
        $this->assertEquals('KEY', $jwk->get('kid'));
        $this->assertEquals('ECDH-ES', $jwk->get('alg'));
        $this->assertEquals('enc', $jwk->get('use'));
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

        $this->assertEquals('OKP', $jwk->get('kty'));
        $this->assertTrue($jwk->has('x'));
        $this->assertTrue($jwk->has('d'));
        $this->assertEquals('KEY', $jwk->get('kid'));
        $this->assertEquals('EdDSA', $jwk->get('alg'));
        $this->assertEquals('sig', $jwk->get('use'));
    }
}
