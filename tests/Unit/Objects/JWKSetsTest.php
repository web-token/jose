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
use Jose\Object\JWKSets;

/**
 * Class JWKSetsTest.
 *
 * @group Unit
 * @group JWKSets
 */
class JWKSetsTest extends \PHPUnit_Framework_TestCase
{
    public function testKey()
    {
        $jwkset1 = JWKFactory::createStorableKeySet(
            sys_get_temp_dir().'/keyset1',
            [
                'kty' => 'EC',
                'crv' => 'P-256',
            ],
            2
        );
        $jwkset2 = JWKFactory::createStorableKeySet(
            sys_get_temp_dir().'/keyset2',
            [
                'kty' => 'RSA',
                'size' => 4096,
            ],
            2
        );
        $jwkset3 = JWKFactory::createStorableKeySet(
            sys_get_temp_dir().'/keyset3',
            [
                'kty' => 'oct',
                'size' => 512,
            ],
            2
        );

        $jwkset = new JWKSets([$jwkset1, $jwkset2]);
        $jwkset->addKeySet($jwkset3);

        $this->assertEquals(6, $jwkset->countKeys());

        $jwkset->addKey(JWKFactory::createRSAKey(['size' => 384]));
        $this->assertEquals(6, $jwkset->countKeys());

        $jwkset->removeKey(0);
        $this->assertEquals(6, $jwkset->countKeys());

        for ($i = 0; $i < 2; ++$i) {
            $this->assertEquals(json_encode($jwkset[$i]), json_encode($jwkset1->getKey($i)));
        }
        for ($i = 2; $i < 4; ++$i) {
            $this->assertEquals(json_encode($jwkset[$i]), json_encode($jwkset2->getKey($i - 2)));
        }
        for ($i = 4; $i < 6; ++$i) {
            $this->assertEquals(json_encode($jwkset[$i]), json_encode($jwkset3->getKey($i - 4)));
        }

        $jwkset1->delete();
        $jwkset2->delete();
        $jwkset3->delete();
    }
}
