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
use Jose\Test\BaseTestCase;

/**
 * @group OctKeys
 * @group Unit
 */
class OctKeysBaseTest extends BaseTestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid key size.
     */
    public function testCreateOctKeyWithInvalidKeySize()
    {
        JWKFactory::createOctKey(['size' => 12]);
    }

    public function testCreateOctKey()
    {
        $jwk = JWKFactory::createOctKey(['size' => 64]);

        self::assertEquals('oct', $jwk->get('kty'));
        self::assertTrue($jwk->has('k'));
    }
}
