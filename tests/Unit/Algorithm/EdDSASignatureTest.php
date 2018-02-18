<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Base64Url\Base64Url;
use Jose\Algorithm\Signature\EdDSA;
use Jose\Factory\JWSFactory;
use Jose\Loader;
use Jose\Object\JWK;
use Jose\Object\JWSInterface;
use Jose\Test\TestCase;
use Jose\Verifier;

/**
 * Class EdDSASignatureTest.
 *
 * @group EdDSA
 * @group Unit
 */
class EdDSASignatureTest extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-00#appendix-A.5
     */
    public function testEdDSAVerifyAlgorithm()
    {
        if (!function_exists('ed25519_sign')) {
            $this->markTestSkipped('EdDSA extension not available');
        }

        $key = new JWK([
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'd' => 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
            'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        ]);

        $eddsa = new EdDSA();
        $input = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
        $signature = Base64Url::decode('hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg');

        $eddsa->verify($key, $input, $signature);
    }

    /**
     * @see https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-00#appendix-A.5
     */
    public function testEdDSASignAndVerifyAlgorithm()
    {
        if (!function_exists('ed25519_sign')) {
            $this->markTestSkipped('EdDSA extension not available');
        }

        $key = new JWK([
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'd' => 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
            'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        ]);

        $header = ['alg' => 'EdDSA'];
        $input = Base64Url::decode('RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc');

        $jws = JWSFactory::createJWSToCompactJSON($input, $key, $header);

        $this->assertEquals('eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg', $jws);

        $loader = new Loader();
        $loaded = $loader->load($jws);
        $verifier = Verifier::createVerifier(['EdDSA']);

        $this->assertInstanceOf(JWSInterface::class, $loaded);
        $this->assertEquals(1, $loaded->countSignatures());
        $verifier->verifyWithKey($loaded, $key);
    }
}
