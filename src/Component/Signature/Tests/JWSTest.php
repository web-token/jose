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

/**
 * final class JWSTest.
 *
 * @group JWS
 * @group Unit
 */
final class JWSTest extends AbstractSignatureTest
{
    public function testJWS()
    {
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $headers = ['alg' => 'none'];
        $jws = JWS::create(json_encode($claims))
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->assertEquals(json_encode($claims), $jws->getPayload());
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
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        JWS::create(json_encode($claims))->toCompactJSON(0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The signature does not exist.
     */
    public function testToFlattenedJSONFailed()
    {
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        JWS::create(json_encode($claims))->toFlattenedJSON(0);
    }

    /**
     * @expectedException \LogicException
     * @expectedExceptionMessage No signature.
     */
    public function testToJSONFailed()
    {
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        JWS::create(json_encode($claims))->toJSON();
    }

    /**
     * @expectedException \LogicException
     * @expectedExceptionMessage The signature contains unprotected headers and cannot be converted into compact JSON
     */
    public function testSignatureContainsUnprotectedHeaders()
    {
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $headers = ['alg' => 'none'];
        $jws = JWS::create(json_encode($claims))
            ->addSignature('', Base64Url::encode(json_encode($headers)), ['foo' => 'bar']);

        $jws->toCompactJSON(0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The header "foo" does not exist
     */
    public function testSignatureDoesNotContainHeader()
    {
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $headers = ['alg' => 'none'];
        $jws = JWS::create(json_encode($claims))
            ->addSignature('', Base64Url::encode(json_encode($headers)));
        $jws->getSignature(0)->getHeader('foo');
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The protected header "foo" does not exist
     */
    public function testSignatureDoesNotContainProtectedHeader()
    {
        $claims = [
            'nbf' => time(),
            'iat' => time(),
            'exp' => time() + 3600,
            'iss' => 'Me',
            'aud' => 'You',
            'sub' => 'My friend',
        ];
        $headers = ['alg' => 'none'];
        $jws = JWS::create(json_encode($claims))
            ->addSignature('', Base64Url::encode(json_encode($headers)));
        $jws->getSignature(0)->getProtectedHeader('foo');
    }
}
