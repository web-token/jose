<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Factory\JWEFactory;

/**
 * Class JWETest.
 *
 * @group JWE
 * @group Unit
 */
class JWETest extends \PHPUnit_Framework_TestCase
{
    public function testJWE()
    {
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jwe = JWEFactory::createJWE($claims);

        $this->assertEquals(0, $jwe->countRecipients());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The recipient does not exist.
     */
    public function testToCompactJSONFailed()
    {
        $jwe = JWEFactory::createJWE([
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ]);

        $jwe->toCompactJSON(0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The shared protected header "plic" does not exist.
     */
    public function testAddAndGetSharedProtectedHeader()
    {
        $jwe = JWEFactory::createJWE([]);
        $jwe = $jwe->withSharedProtectedHeader('foo', 'bar');

        $this->assertEquals(['foo' => 'bar'], $jwe->getSharedProtectedHeaders());
        $this->assertEquals('bar', $jwe->getSharedProtectedHeader('foo'));
        $this->assertEquals('bar', $jwe->getSharedProtectedHeader('plic'));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The shared header "plic" does not exist.
     */
    public function testAddSharedProtectedHeader()
    {
        $jwe = JWEFactory::createJWE([]);
        $jwe = $jwe->withSharedHeader('foo', 'bar');

        $this->assertEquals(['foo' => 'bar'], $jwe->getSharedHeaders());
        $this->assertEquals('bar', $jwe->getSharedHeader('foo'));
        $this->assertEquals('bar', $jwe->getSharedHeader('plic'));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage This JWE has AAD and cannot be converted into Compact JSON.
     */
    public function testCannotGetCompactJSONBecauseAADIsSet()
    {
        $jwe = JWEFactory::createJWE([], [], [], 'foo');
        $jwe = $jwe->addRecipientWithEncryptedKey(null, []);

        $jwe->toCompactJSON(0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage This JWE does not have shared protected headers and cannot be converted into Compact JSON.
     */
    public function testCannotGetCompactJSONBecauseSharedProtectedHeadersAreNotSet()
    {
        $jwe = JWEFactory::createJWE([], [], ['foo' => 'bar']);
        $jwe = $jwe->addRecipientWithEncryptedKey(null, []);

        $jwe->toCompactJSON(0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage This JWE has shared headers or recipient headers and cannot be converted into Compact JSON.
     */
    public function testCannotGetCompactJSONBecauseSharedHeadersAreSet()
    {
        $jwe = JWEFactory::createJWE([], ['plic' => 'ploc'], ['foo' => 'bar']);
        $jwe = $jwe->addRecipientWithEncryptedKey(null, []);

        $jwe->toCompactJSON(0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage This JWE has shared headers or recipient headers and cannot be converted into Compact JSON.
     */
    public function testCannotGetCompactJSONBecauseRecipientHeadersAreSet()
    {
        $jwe = JWEFactory::createJWE([], ['plic' => 'ploc']);
        $jwe = $jwe->addRecipientWithEncryptedKey(null, ['foo' => 'bar']);

        $jwe->toCompactJSON(0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The header "var" does not exist.
     */
    public function testRecipient()
    {
        $jwe = JWEFactory::createJWE([]);
        $jwe = $jwe->addRecipientWithEncryptedKey(null, [
            'foo' => 'bar',
            'plic' => 'ploc',
        ]);

        $this->assertEquals(1, $jwe->countRecipients());
        $this->assertEquals('bar', $jwe->getRecipient(0)->getHeader('foo'));
        $this->assertEquals('ploc', $jwe->getRecipient(0)->getHeader('plic'));
        $jwe->getRecipient(0)->getHeader('var');
    }
}
