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

/**
 * Class StorableJWKTest.
 *
 * @group Unit
 * @group StorableJWK
 */
class StorableJWKTest extends \Jose\Test\BaseTestCase
{
    public function testKey()
    {
        @unlink(sys_get_temp_dir().'/JWK.key');
        $jwk = JWKFactory::createStorableKey(
            sys_get_temp_dir().'/JWK.key',
            [
                'kty' => 'EC',
                'crv' => 'P-256',
            ]
        );

        $all = $jwk->getAll();
        self::assertEquals($all, $jwk->getAll());
        self::assertTrue($jwk->has('kty'));
        self::assertTrue($jwk->has('crv'));
        self::assertEquals('EC', $jwk->get('kty'));
        self::assertEquals('P-256', $jwk->get('crv'));
        self::assertTrue(is_string($jwk->thumbprint('sha256')));
        self::assertTrue(is_string(json_encode($jwk)));
        self::assertInstanceOf(\Jose\Object\JWKInterface::class, $jwk->toPublic());

        self::assertEquals($all, $jwk->getAll());

        $jwk->regen();

        self::assertNotEquals($all, $jwk->getAll());
        $all = $jwk->getAll();
        self::assertEquals($all, $jwk->getAll());

        $jwk->delete();
    }
}
