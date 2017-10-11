<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
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
class RotatableJWKSetTest extends \Jose\Test\BaseTestCase
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

        self::assertEquals(3, $jwkset->count());
        self::assertEquals(3, $jwkset->countKeys());

        self::assertInstanceOf(JWKInterface::class, $jwkset[0]);
        self::assertInstanceOf(JWKInterface::class, $jwkset[1]);
        self::assertInstanceOf(JWKInterface::class, $jwkset[2]);
        self::assertFalse(isset($jwkset[3]));
        self::assertTrue($jwkset->hasKey(0));
        self::assertEquals($jwkset->getKey(0), $jwkset[0]);
        foreach ($jwkset->getKeys() as $key) {
            self::assertInstanceOf(JWKInterface::class, $key);
        }
        foreach ($jwkset as $key) {
            self::assertInstanceOf(JWKInterface::class, $key);
        }

        $actual_content = json_encode($jwkset);

        self::assertEquals($actual_content, json_encode($jwkset));

        $jwkset->rotate();

        self::assertNotEquals($actual_content, json_encode($jwkset));

        $actual_content = json_encode($jwkset);

        $jwkset[] = JWKFactory::createKey(['kty' => 'EC', 'crv' => 'P-521']);
        self::assertEquals(3, $jwkset->count());
        self::assertEquals(3, $jwkset->countKeys());
        self::assertEquals($actual_content, json_encode($jwkset));

        unset($jwkset[count($jwkset) - 1]);
        self::assertEquals(3, $jwkset->count());
        self::assertEquals(3, $jwkset->countKeys());
        self::assertEquals($actual_content, json_encode($jwkset));

        $jwkset->addKey(JWKFactory::createKey(['kty' => 'EC', 'crv' => 'P-521']));
        self::assertEquals(3, $jwkset->count());
        self::assertEquals(3, $jwkset->countKeys());
        self::assertEquals($actual_content, json_encode($jwkset));

        $jwkset->prependKey(JWKFactory::createKey(['kty' => 'EC', 'crv' => 'P-521']));
        self::assertEquals(3, $jwkset->count());
        self::assertEquals(3, $jwkset->countKeys());
        self::assertEquals($actual_content, json_encode($jwkset));

        $jwkset->removeKey(count($jwkset) - 1);
        self::assertEquals(3, $jwkset->count());
        self::assertEquals(3, $jwkset->countKeys());
        self::assertEquals($actual_content, json_encode($jwkset));

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

        self::assertEquals(3, $jwkset->count());
        self::assertEquals(3, $jwkset->countKeys());

        $before_rotate = json_decode(json_encode($jwkset))->keys;

        // Sleep to ensure next calls trigger rotation
        sleep(2);

        // Make sure that a manual call to getKeys triggered rotation
        $after_rotate = json_decode(json_encode($jwkset->getKeys()));

        self::assertCount(3, $after_rotate);
        self::assertEquals($before_rotate[0], $after_rotate[1]);
        self::assertEquals($before_rotate[1], $after_rotate[2]);

        // Sleep to ensure next calls trigger rotation
        sleep(2);

        // Make sure that json serialization also triggered rotation
        $after_second_rotate = json_decode(json_encode($jwkset))->keys;

        self::assertCount(3, $after_second_rotate);
        self::assertEquals($after_rotate[0], $after_second_rotate[1]);
        self::assertEquals($after_rotate[1], $after_second_rotate[2]);

        // Make sure that subsequent calls to get keys within the interval period do not trigger rotation
        self::assertEquals($after_second_rotate, json_decode(json_encode($jwkset->getKeys())));
        self::assertEquals($after_second_rotate, json_decode(json_encode($jwkset))->keys);
    }
}
