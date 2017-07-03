<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\Unit\Keys;

use Jose\Component\KeyManagement\JWKFactory;
use Jose\Test\TestCase;

/**
 * @group OctKeys
 * @group Unit
 */
final class OctKeysTest extends TestCase
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

        $this->assertEquals('oct', $jwk->get('kty'));
        $this->assertTrue($jwk->has('k'));
    }
}