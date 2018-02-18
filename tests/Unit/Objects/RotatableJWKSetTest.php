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
use Jose\Object\JWKInterface;

/**
 * Class RotatableJWKSetTest.
 *
 * @group Unit
 * @group StorableJWKSet
 * @group RotatableJWKSet
 */
class RotatableJWKSetTest extends \PHPUnit_Framework_TestCase
{
    public function testKey()
    {
        @unlink(sys_get_temp_dir().'/JWKSet.key');
        $jwkset = JWKFactory::createRotatableKeySet(
            sys_get_temp_dir().'/JWKSet.key',
            [
                'kty' => 'EC',
                'crv' => 'P-256',
            ],
            3
        );

        $this->assertEquals(3, $jwkset->count());
        $this->assertEquals(3, $jwkset->countKeys());

        $this->assertInstanceOf(JWKInterface::class, $jwkset[0]);
        $this->assertInstanceOf(JWKInterface::class, $jwkset[1]);
        $this->assertInstanceOf(JWKInterface::class, $jwkset[2]);
        $this->assertFalse(isset($jwkset[3]));
        $this->assertTrue($jwkset->hasKey(0));
        $this->assertEquals($jwkset->getKey(0), $jwkset[0]);
        foreach ($jwkset->getKeys() as $key) {
            $this->assertInstanceOf(JWKInterface::class, $key);
        }
        foreach ($jwkset as $key) {
            $this->assertInstanceOf(JWKInterface::class, $key);
        }

        $actual_content = json_encode($jwkset);

        $this->assertEquals($actual_content, json_encode($jwkset));

        $jwkset->rotate();

        $this->assertNotEquals($actual_content, json_encode($jwkset));

        $actual_content = json_encode($jwkset);

        $jwkset[] = JWKFactory::createKey(['kty' => 'EC', 'crv' => 'P-521']);
        $this->assertEquals(3, $jwkset->count());
        $this->assertEquals(3, $jwkset->countKeys());
        $this->assertEquals($actual_content, json_encode($jwkset));

        unset($jwkset[count($jwkset) - 1]);
        $this->assertEquals(3, $jwkset->count());
        $this->assertEquals(3, $jwkset->countKeys());
        $this->assertEquals($actual_content, json_encode($jwkset));

        $jwkset->addKey(JWKFactory::createKey(['kty' => 'EC', 'crv' => 'P-521']));
        $this->assertEquals(3, $jwkset->count());
        $this->assertEquals(3, $jwkset->countKeys());
        $this->assertEquals($actual_content, json_encode($jwkset));

        $jwkset->prependKey(JWKFactory::createKey(['kty' => 'EC', 'crv' => 'P-521']));
        $this->assertEquals(3, $jwkset->count());
        $this->assertEquals(3, $jwkset->countKeys());
        $this->assertEquals($actual_content, json_encode($jwkset));

        $jwkset->removeKey(count($jwkset) - 1);
        $this->assertEquals(3, $jwkset->count());
        $this->assertEquals(3, $jwkset->countKeys());
        $this->assertEquals($actual_content, json_encode($jwkset));

        $jwkset->delete();
    }

    public function testKeyInterval()
    {
        @unlink(sys_get_temp_dir().'/JWKSet.key');
        $jwkset = JWKFactory::createRotatableKeySet(
            sys_get_temp_dir().'/JWKSet.key',
            [
                'kty' => 'EC',
                'crv' => 'P-256',
            ],
            3,
            1 // 1 second rotation interval
        );

        $this->assertEquals(3, $jwkset->count());
        $this->assertEquals(3, $jwkset->countKeys());

        $before_rotate = json_decode(json_encode($jwkset))->keys;

        // Sleep to ensure next calls trigger rotation
        sleep(2);

        // Make sure that a manual call to getKeys triggered rotation
        $after_rotate = json_decode(json_encode($jwkset->getKeys()));

        $this->assertCount(3, $after_rotate);
        $this->assertEquals($before_rotate[0], $after_rotate[1]);
        $this->assertEquals($before_rotate[1], $after_rotate[2]);

        // Sleep to ensure next calls trigger rotation
        sleep(2);

        // Make sure that json serialization also triggered rotation
        $after_second_rotate = json_decode(json_encode($jwkset))->keys;

        $this->assertCount(3, $after_second_rotate);
        $this->assertEquals($after_rotate[0], $after_second_rotate[1]);
        $this->assertEquals($after_rotate[1], $after_second_rotate[2]);

        // Make sure that subsequent calls to get keys within the interval period do not trigger rotation
        $this->assertEquals($after_second_rotate, json_decode(json_encode($jwkset->getKeys())));
        $this->assertEquals($after_second_rotate, json_decode(json_encode($jwkset))->keys);
    }
}
