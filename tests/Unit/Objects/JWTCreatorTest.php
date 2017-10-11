<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

/**
 * Class JWETest.
 *
 * @group JWTCreator
 * @group Unit
 */
class JWTCreatorTest extends \Jose\Test\BaseTestCase
{
    public function testMethods()
    {
        $signer = \Jose\Signer::createSigner(['HS256']);
        $encrypter = \Jose\Encrypter::createEncrypter(['A256GCMKW', 'A256KW'], ['A128GCM']);
        $jwt_creator = new \Jose\JWTCreator($signer);
        $jwt_creator->enableEncryptionSupport($encrypter);

        self::assertEquals(['DEF', 'ZLIB', 'GZ'], $jwt_creator->getSupportedCompressionMethods());
        self::assertEquals(['HS256'], $jwt_creator->getSupportedSignatureAlgorithms());
        self::assertEquals(['A256GCMKW', 'A256KW'], $jwt_creator->getSupportedKeyEncryptionAlgorithms());
        self::assertEquals(['A128GCM'], $jwt_creator->getSupportedContentEncryptionAlgorithms());
        self::assertTrue($jwt_creator->isEncryptionSupportEnabled());

        $payload = 'Hello World!';
        $signature_key = \Jose\Factory\JWKFactory::createKey(['kty' => 'oct', 'use' => 'sig', 'size' => 512]);
        $encryption_key = \Jose\Factory\JWKFactory::createKey(['kty' => 'oct', 'use' => 'enc', 'size' => 256]);

        $jwt = $jwt_creator->signAndEncrypt($payload, ['alg' => 'HS256'], $signature_key, ['alg' => 'A256GCMKW', 'enc' => 'A128GCM'], $encryption_key);
        self::assertEquals(5, count(explode('.', $jwt)));
    }
}
