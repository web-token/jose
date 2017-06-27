<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Tests;

use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Core\JWAManager;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Component\Encryption\Compression\CompressionManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\Decrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Test\TestCase;

/**
 * @group CVE
 * @group Functional
 */
final class InvalidCurveAttackTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unable to decrypt the JWE.
     */
    public function testCurveCheckNegativeP256AttackPt1()
    {
        $maliciousJWE = 'eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiZ1RsaTY1ZVRRN3otQmgxNDdmZjhLM203azJVaURpRzJMcFlrV0FhRkpDYyIsInkiOiJjTEFuakthNGJ6akQ3REpWUHdhOUVQclJ6TUc3ck9OZ3NpVUQta2YzMEZzIiwiY3J2IjoiUC0yNTYifX0.qGAdxtEnrV_3zbIxU2ZKrMWcejNltjA_dtefBFnRh9A2z9cNIqYRWg.pEA5kX304PMCOmFSKX_cEg.a9fwUrx2JXi1OnWEMOmZhXd94-bEGCH9xxRwqcGuG2AMo-AwHoljdsH5C_kcTqlXS5p51OB1tvgQcMwB5rpTxg.72CHiYFecyDvuUa43KKT6w';
        $keyEncryptionAlgorithmManager = JWAManager::create([new ECDHESA128KW()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A128CBCHS256()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $loaded_compact_json = JWELoader::load($maliciousJWE);
        $privateKey = JWKFactory::createECKey([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);
        $decrypter->decryptUsingKey($loaded_compact_json, $privateKey);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unable to decrypt the JWE.
     */
    public function testCurveCheckNegativeP256AttackPt2()
    {
        // The malicious JWE contains a public key with order 2447
        $maliciousJWE = 'eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiWE9YR1E5XzZRQ3ZCZzN1OHZDSS1VZEJ2SUNBRWNOTkJyZnFkN3RHN29RNCIsInkiOiJoUW9XTm90bk56S2x3aUNuZUprTElxRG5UTnc3SXNkQkM1M1ZVcVZqVkpjIiwiY3J2IjoiUC0yNTYifX0.UGb3hX3ePAvtFB9TCdWsNkFTv9QWxSr3MpYNiSBdW630uRXRBT3sxw.6VpU84oMob16DxOR98YTRw.y1UslvtkoWdl9HpugfP0rSAkTw1xhm_LbK1iRXzGdpYqNwIG5VU33UBpKAtKFBoA1Kk_sYtfnHYAvn-aes4FTg.UZPN8h7FcvA5MIOq-Pkj8A';
        $keyEncryptionAlgorithmManager = JWAManager::create([new ECDHESA128KW()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A128CBCHS256()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $loaded_compact_json = JWELoader::load($maliciousJWE);
        $privateKey = JWKFactory::createECKey([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);
        $decrypter->decryptUsingKey($loaded_compact_json, $privateKey);
    }
}
