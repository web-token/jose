<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Factory\JWKFactory;
use Jose\Object\PublicJWKSet;

/**
 * Class PublicJWKSetTest.
 *
 * @group Unit
 * @group PublicJWKSet
 */
class PublicJWKSetTest extends \PHPUnit_Framework_TestCase
{
    public function testKey()
    {
        @unlink(sys_get_temp_dir().'/Public_JWKSet.keyset');
        $jwkset = JWKFactory::createRotatableKeySet(
            sys_get_temp_dir().'/Public_JWKSet.keyset',
            [
                'kty' => 'EC',
                'crv' => 'P-256',
            ],
            3,
            10
        );

        $public_jwkset = new PublicJWKSet($jwkset);

        $this->assertEquals(3, $public_jwkset->countKeys());
        foreach ($public_jwkset as $key) {
            $this->assertEquals(json_encode($key), json_encode($key->toPublic()));
        }
    }
}
