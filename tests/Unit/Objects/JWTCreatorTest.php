<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\Unit\Objects;

use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Core\JWAManager;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Encryption\Compression\CompressionManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\Compression\GZip;
use Jose\Component\Encryption\Compression\ZLib;
use Jose\Component\Encryption\Encrypter;
use Jose\Factory\JWKFactory;
use Jose\JWTCreator;
use Jose\Component\Signature\Signer;
use PHPUnit\Framework\TestCase;

/**
 * final class JWETest.
 *
 * @group JWTCreator
 * @group Unit
 */
final class JWTCreatorTest extends TestCase
{
    public function testMethods()
    {
        $signatureAlgorithmManager = JWAManager::create([new HS256()]);
        $signer = new Signer($signatureAlgorithmManager);

        $keyEncryptionAlgorithmManager = JWAManager::create([new A256GCMKW(), new A256KW()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A128GCM()]);
        $compressionManager = CompressionManager::create([new Deflate(), new ZLib(), new GZip()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);
        $jwt_creator = new JWTCreator($signer);
        $jwt_creator->enableEncryptionSupport($encrypter);

        $this->assertEquals(['DEF', 'ZLIB', 'GZ'], $jwt_creator->getSupportedCompressionMethods());
        $this->assertEquals(['HS256'], $jwt_creator->getSupportedSignatureAlgorithms());
        $this->assertEquals(['A256GCMKW', 'A256KW'], $jwt_creator->getSupportedKeyEncryptionAlgorithms());
        $this->assertEquals(['A128GCM'], $jwt_creator->getSupportedContentEncryptionAlgorithms());
        $this->assertTrue($jwt_creator->isEncryptionSupportEnabled());

        $payload = 'Hello World!';
        $signature_key = JWKFactory::createKey(['kty' => 'oct', 'use' => 'sig', 'size' => 512]);
        $encryption_key = JWKFactory::createKey(['kty' => 'oct', 'use' => 'enc', 'size' => 256]);

        $jwt = $jwt_creator->signAndEncrypt($payload, ['alg' => 'HS256'], $signature_key, ['alg' => 'A256GCMKW', 'enc' => 'A128GCM'], $encryption_key);
        $this->assertEquals(5, count(explode('.', $jwt)));
    }
}
