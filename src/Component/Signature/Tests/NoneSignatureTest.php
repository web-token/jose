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

use Jose\Component\Core\JWAManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\JWS;
use Jose\Component\Factory\JWSFactory;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\Signer;
use PHPUnit\Framework\TestCase;

/**
 * final class NoneSignatureTest.
 *
 * @group None
 * @group Unit
 */
final class NoneSignatureTest extends TestCase
{
    public function testNoneSignAndVerifyAlgorithm()
    {
        $key = JWK::create([
            'kty' => 'none',
        ]);

        $none = new None();
        $data = 'Live long and Prosper.';

        $signature = $none->sign($key, $data);

        $this->assertEquals($signature, '');
        $this->assertTrue($none->verify($key, $data, $signature));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Wrong key type.
     */
    public function testInvalidKey()
    {
        $key = JWK::create([
            'kty' => 'EC',
        ]);

        $none = new None();
        $data = 'Live long and Prosper.';

        $none->sign($key, $data);
    }

    public function testNoneSignAndVerifyComplete()
    {
        $jwk = JWK::create([
            'kty' => 'none',
        ]);

        $jws = JWSFactory::createJWS('Live long and Prosper.');
        $jws = $jws->addSignatureInformation($jwk, ['alg' => 'none']);

        $signatureAlgorithmManager = JWAManager::create([new None()]);
        $signer = new Signer($signatureAlgorithmManager);
        $signer->sign($jws);

        $this->assertEquals(1, $jws->countSignatures());

        $compact = $jws->toCompactJSON(0);
        $this->assertTrue(is_string($compact));

        $result = JWSLoader::load($compact);

        $this->assertInstanceOf(JWS::class, $result);

        $this->assertEquals('Live long and Prosper.', $result->getPayload());
        $this->assertEquals(1, $result->countSignatures());
        $this->assertTrue($result->getSignature(0)->hasProtectedHeader('alg'));
        $this->assertEquals('none', $result->getSignature(0)->getProtectedHeader('alg'));
    }
}
