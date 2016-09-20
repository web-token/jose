<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Object\RotatableJWKSet;

/**
 * Class RotatableJWKSetTest.
 *
 * @group Unit
 * @group RotatableJWKSet
 */
class RotatableJWKSetTest extends \PHPUnit_Framework_TestCase
{
    public function testKey()
    {
        @unlink(sys_get_temp_dir().'/JWKSet.key');
        $jwkset = new RotatableJWKSet(
            sys_get_temp_dir().'/JWKSet.key',
            [
                'kty'   => 'EC',
                'crv'   => 'P-256',
            ],
            3,
            10
        );

        $this->assertEquals(sys_get_temp_dir().'/JWKSet.key', $jwkset->getFilename());

        //Other tests to be written
    }
}
