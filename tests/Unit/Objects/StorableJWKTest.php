<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\Unit\Objects;

use Jose\Component\Core\JWKInterface;
use Jose\Factory\JWKFactory;
use PHPUnit\Framework\TestCase;

/**
 * final class StorableJWKTest.
 *
 * @group Unit
 * @group StorableJWK
 */
final class StorableJWKTest extends TestCase
{
    public function testKey()
    {
        @unlink(sys_get_temp_dir().'/JWK.key');
        $jwk = JWKFactory::createStorableKey(
            sys_get_temp_dir().'/JWK.key',
            [
                'kty'   => 'EC',
                'crv'   => 'P-256',
            ]
        );

        $all = $jwk->getAll();
        $this->assertEquals($all, $jwk->getAll());
        $this->assertTrue($jwk->has('kty'));
        $this->assertTrue($jwk->has('crv'));
        $this->assertEquals('EC', $jwk->get('kty'));
        $this->assertEquals('P-256', $jwk->get('crv'));
        $this->assertTrue(is_string($jwk->thumbprint('sha256')));
        $this->assertTrue(is_string(json_encode($jwk)));
        $this->assertInstanceOf(JWKInterface::class, $jwk->toPublic());

        $this->assertEquals($all, $jwk->getAll());

        $jwk->regen();

        $this->assertNotEquals($all, $jwk->getAll());
        $all = $jwk->getAll();
        $this->assertEquals($all, $jwk->getAll());

        $jwk->delete();
    }
}
