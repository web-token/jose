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
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Component\Encryption\Compression\CompressionMethodsManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\Decrypter;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

/**
 * final class ECDHESWithX25519EncryptionTest.
 *
 * @group ECDHES
 * @group Unit
 */
final class ECDHESWithX25519EncryptionTest extends AbstractEncryptionTest
{
    /**
     * @see https://tools.ietf.org/html/rfc7516#appendix-B
     */
    public function testA128CBCHS256EncryptAndDecrypt()
    {
        $receiverKey = JWKFactory::createOKPKey('X25519');
        $input = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $protectedHeaders = [
            'alg' => 'ECDH-ES+A128KW',
            'enc' => 'A128GCM',
        ];

        $keyEncryptionAlgorithmManager = JWAManager::create([new ECDHESA128KW()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A128GCM()]);
        $compressionManager = CompressionMethodsManager::create([new Deflate()]);
        $jweBuilder = $this->getJWEBuilderFactory()->create(['ECDH-ES+A128KW'], ['A128GCM'], ['DEF']);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwt = $jweBuilder
            ->withPayload($input)
            ->withSharedProtectedHeaders($protectedHeaders)
            ->addRecipient($receiverKey)
            ->build()
            ->toCompactJSON(0);

        $jwe = JWELoader::load($jwt);
        $jwe = $decrypter->decryptUsingKey($jwe, $receiverKey, $index);
        $this->assertEquals(0, $index);
        $this->assertTrue($jwe->hasSharedProtectedHeader('epk'));
        $this->assertEquals($input, $jwe->getPayload());
    }
}
