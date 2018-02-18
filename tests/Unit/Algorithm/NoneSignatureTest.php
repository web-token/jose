<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Algorithm\Signature\None;
use Jose\Loader;
use Jose\Object\JWK;
use Jose\Object\JWSInterface;
use Jose\Signer;
use Jose\Test\TestCase;

/**
 * Class NoneSignatureTest.
 *
 * @group None
 * @group Unit
 */
class NoneSignatureTest extends TestCase
{
    public function testNoneSignAndVerifyAlgorithm()
    {
        $key = new JWK([
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
        $key = new JWK([
            'kty' => 'EC',
        ]);

        $none = new None();
        $data = 'Live long and Prosper.';

        $none->sign($key, $data);
    }

    public function testNoneSignAndVerifyComplete()
    {
        $jwk = new JWK([
            'kty' => 'none',
        ]);

        $jws = \Jose\Factory\JWSFactory::createJWS('Live long and Prosper.');
        $jws = $jws->addSignatureInformation($jwk, ['alg' => 'none']);

        $signer = Signer::createSigner(['none']);
        $signer->sign($jws);

        $this->assertEquals(1, $jws->countSignatures());

        $compact = $jws->toCompactJSON(0);
        $this->assertTrue(is_string($compact));

        $loader = new Loader();
        $result = $loader->load($compact);

        $this->assertInstanceOf(JWSInterface::class, $result);

        $this->assertEquals('Live long and Prosper.', $result->getPayload());
        $this->assertEquals(1, $result->countSignatures());
        $this->assertTrue($result->getSignature(0)->hasProtectedHeader('alg'));
        $this->assertEquals('none', $result->getSignature(0)->getProtectedHeader('alg'));
    }
}
