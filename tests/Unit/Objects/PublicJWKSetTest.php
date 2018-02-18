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
            3
        );

        $public_jwkset = new PublicJWKSet($jwkset);

        $this->assertEquals(3, $public_jwkset->countKeys());
        foreach ($public_jwkset as $key) {
            $this->assertEquals(json_encode($key), json_encode($key->toPublic()));
        }

        $jwkset->delete();
    }

    public function testWithMultipleKeySets()
    {
        @unlink(sys_get_temp_dir().'/keyset1.1');
        @unlink(sys_get_temp_dir().'/keyset2.2');
        @unlink(sys_get_temp_dir().'/keyset3.3');
        $jwkset1 = JWKFactory::createRotatableKeySet(
            sys_get_temp_dir().'/keyset1.1',
            [
                'kty' => 'EC',
                'crv' => 'P-256',
            ],
            3
        );
        $jwkset2 = JWKFactory::createRotatableKeySet(
            sys_get_temp_dir().'/keyset2.2',
            [
                'kty' => 'oct',
                'size' => 256,
            ],
            2
        );
        $jwkset3 = JWKFactory::createRotatableKeySet(
            sys_get_temp_dir().'/keyset3.3',
            [
                'kty' => 'RSA',
                'size' => 4096,
            ],
            4
        );

        $jwksets = new \Jose\Object\JWKSets([$jwkset1, $jwkset2, $jwkset3]);
        $public_jwkset = new PublicJWKSet($jwksets);

        $this->assertEquals(7, $public_jwkset->countKeys());

        $public_jwkset->addKey(JWKFactory::createRSAKey(['size' => 384]));
        $this->assertEquals(7, $public_jwkset->countKeys());

        $public_jwkset->removeKey(0);
        $this->assertEquals(7, $public_jwkset->countKeys());

        $this->assertEquals(7, count($public_jwkset->toPEM()));

        foreach ($public_jwkset as $key) {
            $this->assertEquals(json_encode($key), json_encode($key->toPublic()));
        }
        for ($i = 0; $i < 3; ++$i) {
            $this->assertEquals(json_encode($public_jwkset[$i]), json_encode($jwkset1->getKey($i)->toPublic()));
        }
        for ($i = 3; $i < 7; ++$i) {
            $this->assertEquals(json_encode($public_jwkset[$i]), json_encode($jwkset3->getKey($i - 3)->toPublic()));
        }

        $jwkset1->delete();
        $jwkset2->delete();
        $jwkset3->delete();
    }
}
