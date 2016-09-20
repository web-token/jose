<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Object\RotatableJWK;

/**
 * Class RotatableJWKTest.
 *
 * @group Unit
 * @group RotatableJWK
 */
class RotatableJWKTest extends \PHPUnit_Framework_TestCase
{
    public function testKey()
    {
        @unlink(sys_get_temp_dir().'/JWK.key');
        $jwk = new RotatableJWK(
            sys_get_temp_dir().'/JWK.key',
            [
                'kty'   => 'EC',
                'crv'   => 'P-256',
            ],
            10
        );

        $this->assertEquals(sys_get_temp_dir().'/JWK.key', $jwk->getFilename());
        $all = $jwk->getAll();
        $this->assertEquals($all, $jwk->getAll());
        $this->assertTrue($jwk->has('kty'));
        $this->assertTrue($jwk->has('crv'));
        $this->assertEquals('EC', $jwk->get('kty'));
        $this->assertEquals('P-256', $jwk->get('crv'));
        $this->assertTrue(is_string($jwk->thumbprint('sha256')));
        $this->assertTrue(is_string(json_encode($jwk)));
        $this->assertInstanceOf(\Jose\Object\JWKInterface::class, $jwk->toPublic());

        sleep(5);

        $this->assertEquals($all, $jwk->getAll());

        sleep(6);

        $this->assertNotEquals($all, $jwk->getAll());
        $all = $jwk->getAll();
        $this->assertEquals($all, $jwk->getAll());
    }
}
