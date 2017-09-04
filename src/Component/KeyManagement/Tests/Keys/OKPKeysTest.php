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

namespace Jose\Test\Unit\Keys;

use Jose\Component\Core\JWKFactory;
use PHPUnit\Framework\TestCase;

/**
 * @group OKPKeys
 * @group Unit
 */
final class OKPKeysTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unsupported "Ed455" curve
     */
    public function testCreateOKPKeyWithInvalidKeySize()
    {
        JWKFactory::createOKPKey('Ed455');
    }

    public function testCreateOKPKeyWithCurveX25519()
    {
        $jwk = JWKFactory::createOKPKey(
            'X25519',
            [
                'kid' => 'KEY',
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
        $jwk = JWKFactory::createOKPKey(
            'Ed25519',
            [
                'kid' => 'KEY',
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
