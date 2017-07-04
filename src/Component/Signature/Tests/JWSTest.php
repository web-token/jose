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

namespace Jose\Component\Signature\Tests;

use Base64Url\Base64Url;
use Jose\Component\Signature\JWS;
use PHPUnit\Framework\TestCase;

/**
 * final class JWSTest.
 *
 * @group JWS
 * @group Unit
 */
final class JWSTest extends TestCase
{
    public function testJWS()
    {
        $jws = new JWS();
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $headers = ['alg' => 'none'];
        $jws = $jws->addSignatureFromLoadedData('', Base64Url::encode(json_encode($headers)), []);
        $jws = $jws->withPayload($claims);

        $this->assertTrue($jws->hasClaims());
        $this->assertTrue($jws->hasClaim('nbf'));
        $this->assertTrue($jws->hasClaim('iss'));
        $this->assertEquals('Me', $jws->getClaim('iss'));
        $this->assertEquals($claims, $jws->getPayload());
        $this->assertEquals($claims, $jws->getClaims());
        $this->assertEquals(1, $jws->countSignatures());
        $this->assertTrue($jws->getSignature(0)->hasProtectedHeader('alg'));
        $this->assertEquals($headers, $jws->getSignature(0)->getProtectedHeaders());
        $this->assertEquals('none', $jws->getSignature(0)->getProtectedHeader('alg'));
        $this->assertEquals([], $jws->getSignature(0)->getHeaders());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The signature does not exist.
     */
    public function testToCompactJSONFailed()
    {
        $jws = new JWS();
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jws = $jws->withPayload($claims);
        $jws->toCompactJSON(0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The signature does not exist.
     */
    public function testToFlattenedJSONFailed()
    {
        $jws = new JWS();
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jws = $jws->withPayload($claims);
        $jws->toFlattenedJSON(0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage No signature.
     */
    public function testToJSONFailed()
    {
        $jws = new JWS();
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jws = $jws->withPayload($claims);
        $jws->toJSON();
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The payload does not contain claims.
     */
    public function testNoClaims()
    {
        $jws = new JWS();
        $payload = 'Hello World!';
        $jws = $jws->withPayload($payload);
        $jws->getClaims();
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The payload does not contain claim "foo".
     */
    public function testClaimDoesNotExist()
    {
        $jws = new JWS();
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $jws = $jws->withPayload($claims);
        $jws->getClaim('foo');
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The signature contains unprotected headers and cannot be converted into compact JSON
     */
    public function testSignatureContainsUnprotectedHeaders()
    {
        $jws = new JWS();
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $headers = ['alg' => 'none'];
        $jws = $jws->addSignatureFromLoadedData('', Base64Url::encode(json_encode($headers)), ['foo' => 'bar']);
        $jws = $jws->withPayload($claims);

        $jws->toCompactJSON(0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The header "foo" does not exist
     */
    public function testSignatureDoesNotContainHeader()
    {
        $jws = new JWS();
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $headers = ['alg' => 'none'];
        $jws = $jws->addSignatureFromLoadedData('', Base64Url::encode(json_encode($headers)), []);
        $jws = $jws->withPayload($claims);
        $jws->getSignature(0)->getHeader('foo');
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The protected header "foo" does not exist
     */
    public function testSignatureDoesNotContainProtectedHeader()
    {
        $jws = new JWS();
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $headers = ['alg' => 'none'];
        $jws = $jws->addSignatureFromLoadedData('', Base64Url::encode(json_encode($headers)), []);
        $jws = $jws->withPayload($claims);
        $jws->getSignature(0)->getProtectedHeader('foo');
    }
}
