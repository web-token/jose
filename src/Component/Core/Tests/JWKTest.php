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

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use PHPUnit\Framework\TestCase;

/**
 * final class JWKTest.
 *
 * @group Unit
 * @group JWK
 */
final class JWKTest extends TestCase
{
    public function testKey()
    {
        $jwk = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'bar' => 'plic',
        ]);

        $this->assertEquals('EC', $jwk->get('kty'));
        $this->assertEquals('ES256', $jwk->get('alg'));
        $this->assertEquals('sign', $jwk->get('use'));
        $this->assertFalse($jwk->has('kid'));
        $this->assertEquals(['sign'], $jwk->get('key_ops'));
        $this->assertEquals('P-256', $jwk->get('crv'));
        $this->assertFalse($jwk->has('x5u'));
        $this->assertFalse($jwk->has('x5c'));
        $this->assertFalse($jwk->has('x5t'));
        $this->assertFalse($jwk->has('x5t#256'));
        $this->assertEquals('f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', $jwk->get('x'));
        $this->assertEquals('x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0', $jwk->get('y'));
        $this->assertEquals('{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sign","key_ops":["sign"],"alg":"ES256","bar":"plic"}', json_encode($jwk));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The parameter "kty" is mandatory.
     */
    public function testBadConstruction()
    {
        JWK::create([]);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The value identified by "ABCD" does not exist.
     */
    public function testBadCall()
    {
        $jwk = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'bar' => 'plic',
        ]);

        $jwk->get('ABCD');
    }

    public function testKeySet()
    {
        $jwk1 = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'kid' => '0123456789',
        ]);

        $jwk2 = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use' => 'sign',
            'key_ops' => ['verify'],
            'alg' => 'ES256',
            'kid' => '9876543210',
        ]);

        $jwkset = JWKSet::createFromKeys([$jwk1]);
        $jwkset = $jwkset->with($jwk2);

        $this->assertEquals('{"keys":{"0123456789":{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sign","key_ops":["sign"],"alg":"ES256","kid":"0123456789"},"9876543210":{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI","use":"sign","key_ops":["verify"],"alg":"ES256","kid":"9876543210"}}}', json_encode($jwkset));
        $this->assertEquals(2, count($jwkset));
        $this->assertEquals(2, $jwkset->count());
        $this->assertTrue($jwkset->has('0123456789'));
        $this->assertTrue($jwkset->has('9876543210'));
        $this->assertFalse($jwkset->has(0));

        foreach ($jwkset as $key) {
            $this->assertEquals('EC', $key->get('kty'));
        }
        $this->assertEquals(null, $jwkset->key());

        $this->assertEquals('9876543210', $jwkset->get('9876543210')->get('kid'));
        $jwkset = $jwkset->without('9876543210');
        $jwkset = $jwkset->without('9876543210');

        $this->assertEquals(1, count($jwkset));
        $this->assertEquals(1, $jwkset->count());
        $this->assertInstanceOf(JWK::class, $jwkset->get('0123456789'));

        $jwkset = $jwkset->without('0123456789');
        $this->assertEquals(0, count($jwkset));
        $this->assertEquals(0, $jwkset->count());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Undefined index.
     */
    public function testKeySet2()
    {
        $jwk1 = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['sign'],
            'alg' => 'ES256',
            'kid' => '0123456789',
        ]);

        $jwk2 = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use' => 'sign',
            'key_ops' => ['verify'],
            'alg' => 'ES256',
            'kid' => '9876543210',
        ]);

        $jwkset = JWKSet::createFromKeys([$jwk1, $jwk2]);

        $jwkset->get(2);
    }

    public function testPrivateToPublic()
    {
        $private = JWK::create([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
            'use' => 'sign',
            'key_ops' => ['verify'],
            'alg' => 'ES256',
            'kid' => '9876543210',
        ]);

        $public = $private->toPublic();

        $this->assertEquals(json_encode([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'use' => 'sign',
            'key_ops' => ['verify'],
            'alg' => 'ES256',
            'kid' => '9876543210',
        ]), json_encode($public));
    }
}
