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

namespace Jose\Component\Encryption\Tests;

use Jose\Component\Core\JWAManager;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\Compression\CompressionManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\Decrypter;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWELoader;
use Jose\Test\TestCase;

/**
 * final class FlattenedTest.
 *
 * @group Functional
 */
final class JWEFlattenedTest extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7516#appendix-A.5
     */
    public function testLoadFlattenedJWE()
    {
        $keyEncryptionAlgorithmManager = JWAManager::create([new A128KW()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A128CBCHS256()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $loaded = JWELoader::load('{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"jku":"https://server.example.com/keys.jwks"},"header":{"alg":"A128KW","kid":"7"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ","iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}');

        $this->assertInstanceOf(JWE::class, $loaded);
        $this->assertEquals('A128KW', $loaded->getRecipient(0)->getHeader('alg'));
        $this->assertEquals('A128CBC-HS256', $loaded->getSharedProtectedHeader('enc'));
        $this->assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getSymmetricKeySet(), $index);

        $this->assertEquals(0, $index);
        $this->assertEquals('Live long and prosper.', $loaded->getPayload());
    }
}
