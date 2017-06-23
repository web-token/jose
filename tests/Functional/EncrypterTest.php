<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\Functional;

use Base64Url\Base64Url;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192CBCHS384;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Core\JWAManager;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\Compression\CompressionManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\Decrypter;
use Jose\Component\Encryption\Encrypter;
use Jose\Component\Encryption\JWEFactory;
use Jose\Loader;
use Jose\Component\Encryption\JWE;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Test\TestCase;

/**
 * final class EncrypterTest.
 *
 * @group Encrypter
 * @group Functional
 */
final class EncrypterTest extends TestCase
{
    public function testEncryptWithJWTInput()
    {
        $keyEncryptionAlgorithmManager = JWAManager::create([new RSAOAEP256()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256CBCHS512()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE(
            'FOO',
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ],
            [],
            'foo,bar,baz'
        );

        $jwe = $jwe->addRecipientInformation($this->getRSARecipientKey());

        $encrypter->encrypt($jwe);

        $encrypted = $jwe->toFlattenedJSON(0);

        $loader = new Loader();
        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf(JWE::class, $loaded);
        $this->assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        $this->assertEquals('DEF', $loaded->getSharedProtectedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        $this->assertEquals(0, $index);
        $this->assertEquals('FOO', $loaded->getPayload());
    }

    public function testCreateCompactJWEUsingFactory()
    {
        $jwe = JWEFactory::createJWEToCompactJSON(
            'FOO',
            $this->getRSARecipientKey(),
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ]
        );

        $loader = new Loader();
        $loaded = $loader->load($jwe);

        $this->assertInstanceOf(JWE::class, $loaded);
        $this->assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        $this->assertEquals('DEF', $loaded->getSharedProtectedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $keyEncryptionAlgorithmManager = JWAManager::create([new RSAOAEP256()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256CBCHS512()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);
        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        $this->assertEquals(0, $index);
        $this->assertEquals('FOO', $loaded->getPayload());
    }

    public function testCreateFlattenedJWEUsingFactory()
    {
        $jwe = JWEFactory::createJWEToFlattenedJSON(
            'FOO',
            $this->getRSARecipientKey(),
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ],
            [
                'foo' => 'bar',
            ],
            [
                'plic' => 'ploc',
            ],
            'A,B,C,D'
        );

        $loader = new Loader();
        $loaded = $loader->load($jwe);

        $this->assertInstanceOf(JWE::class, $loaded);
        $this->assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        $this->assertEquals('DEF', $loaded->getSharedProtectedHeader('zip'));
        $this->assertEquals('bar', $loaded->getSharedHeader('foo'));
        $this->assertEquals('A,B,C,D', $loaded->getAAD('foo'));
        $this->assertEquals('ploc', $loaded->getRecipient(0)->getHeader('plic'));
        $this->assertNull($loaded->getPayload());

        $keyEncryptionAlgorithmManager = JWAManager::create([new RSAOAEP256()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256CBCHS512()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);
        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        $this->assertEquals(0, $index);
        $this->assertEquals('FOO', $loaded->getPayload());
    }

    public function testEncryptAndLoadFlattenedWithAAD()
    {
        $keyEncryptionAlgorithmManager = JWAManager::create([new RSAOAEP256()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256CBCHS512()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE(
            $this->getKeyToEncrypt(),
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ],
            [],
            'foo,bar,baz'
        );

        $jwe = $jwe->addRecipientInformation($this->getRSARecipientKey());

        $encrypter->encrypt($jwe);

        $encrypted = $jwe->toFlattenedJSON(0);

        $loader = new Loader();
        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf(JWE::class, $loaded);
        $this->assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        $this->assertEquals('DEF', $loaded->getSharedProtectedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        $this->assertEquals(0, $index);
        $this->assertTrue(is_array($loaded->getPayload()));
        $this->assertEquals($this->getKeyToEncrypt(), new JWK($loaded->getPayload()));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The compression method "FIP" is not supported.
     */
    public function testCompressionAlgorithmNotSupported()
    {
        $keyEncryptionAlgorithmManager = JWAManager::create([new RSAOAEP256()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256CBCHS512()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE(
            $this->getKeyToEncrypt(),
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'FIP',
            ],
            [],
            'foo,bar,baz'
        );

        $jwe = $jwe->addRecipientInformation($this->getRSARecipientKey());

        $encrypter->encrypt($jwe);
    }

    public function testMultipleInstructionsNotAllowedWithCompactSerialization()
    {
        $keyEncryptionAlgorithmManager = JWAManager::create([new RSAOAEP(), new RSAOAEP256()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256CBCHS512()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE('Live long and Prosper.');
        $jwe = $jwe->withSharedProtectedHeaders([
            'enc' => 'A256CBC-HS512',
        ]);

        $jwe = $jwe->addRecipientInformation($this->getRSARecipientKeyWithAlgorithm(), ['alg' => 'RSA-OAEP']);
        $jwe = $jwe->addRecipientInformation($this->getRSARecipientKey(), ['alg' => 'RSA-OAEP-256']);

        $encrypter->encrypt($jwe);

        $this->assertEquals(2, $jwe->countRecipients());
    }

    public function testMultipleInstructionsNotAllowedWithFlattenedSerialization()
    {
        $keyEncryptionAlgorithmManager = JWAManager::create([new RSAOAEP256(), new ECDHESA256KW()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256CBCHS512()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE('Live long and Prosper.');
        $jwe = $jwe->withSharedProtectedHeaders([
            'enc' => 'A256CBC-HS512',
        ]);

        $jwe = $jwe->addRecipientInformation(
            $this->getECDHRecipientPublicKey(),
            ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'alg' => 'ECDH-ES+A256KW']
        );
        $jwe = $jwe->addRecipientInformation(
            $this->getRSARecipientKey(),
            ['kid' => '123456789', 'alg' => 'RSA-OAEP-256']
        );

        $encrypter->encrypt($jwe);

        $this->assertEquals(2, $jwe->countRecipients());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Foreign key management mode forbidden.
     */
    public function testForeignKeyManagementModeForbidden()
    {
        $keyEncryptionAlgorithmManager = JWAManager::create([new Dir(), new ECDHESA256KW()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256CBCHS512()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE('Live long and Prosper.');
        $jwe = $jwe->withSharedProtectedHeaders([
            'enc' => 'A256CBC-HS512',
        ]);

        $jwe = $jwe->addRecipientInformation(
            $this->getECDHRecipientPublicKey(),
            ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'alg' => 'ECDH-ES+A256KW']
        );
        $jwe = $jwe->addRecipientInformation(
            $this->getDirectKey(),
            ['kid' => 'DIR_1', 'alg' => 'dir']
        );

        $encrypter->encrypt($jwe);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Key cannot be used to encrypt
     */
    public function testOperationNotAllowedForTheKey()
    {
        $keyEncryptionAlgorithmManager = JWAManager::create([new RSAOAEP256()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256CBCHS512()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE(
            'Foo',
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ],
            [],
            'foo,bar,baz'
        );
        $jwe = $jwe->addRecipientInformation(
            $this->getSigningKey()
        );

        $encrypter->encrypt($jwe);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Key is only allowed for algorithm "RSA-OAEP".
     */
    public function testAlgorithmNotAllowedForTheKey()
    {
        $keyEncryptionAlgorithmManager = JWAManager::create([new RSAOAEP256()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256CBCHS512()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE(
            'FOO',
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'RSA-OAEP-256',
                'zip' => 'DEF',
            ],
            [],
            'foo,bar,baz'
        );
        $jwe = $jwe->addRecipientInformation(
            $this->getRSARecipientKeyWithAlgorithm()
        );

        $encrypter->encrypt($jwe);
    }

    public function testEncryptAndLoadFlattenedWithDeflateCompression()
    {
        $keyEncryptionAlgorithmManager = JWAManager::create([new RSAOAEP256()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A128CBCHS256()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE($this->getKeySetToEncrypt());
        $jwe = $jwe->withSharedProtectedHeaders([
            'kid' => '123456789',
            'enc' => 'A128CBC-HS256',
            'alg' => 'RSA-OAEP-256',
            'zip' => 'DEF',
        ]);
        $jwe = $jwe->addRecipientInformation(
            $this->getRSARecipientKey()
        );

        $encrypter->encrypt($jwe);

        $encrypted = $jwe->toCompactJSON(0);

        $loader = new Loader();
        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf(JWE::class, $loaded);
        $this->assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeader('alg'));
        $this->assertEquals('A128CBC-HS256', $loaded->getSharedProtectedHeader('enc'));
        $this->assertEquals('DEF', $loaded->getSharedProtectedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        $this->assertEquals(0, $index);
        $this->assertTrue(is_array($loaded->getPayload()));
        $this->assertEquals($this->getKeySetToEncrypt(), new JWKSet($loaded->getPayload()));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Parameter "alg" is missing.
     */
    public function testAlgParameterIsMissing()
    {

        $keyEncryptionAlgorithmManager = JWAManager::create([]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256CBCHS512()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE($this->getKeyToEncrypt());
        $jwe = $jwe->withSharedProtectedHeaders([
            'kid' => '123456789',
            'enc' => 'A256CBC-HS512',
            'zip' => 'DEF',
        ]);
        $jwe = $jwe->addRecipientInformation(
            $this->getRSARecipientKey()
        );

        $encrypter->encrypt($jwe);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Parameter "enc" is missing.
     */
    public function testEncParameterIsMissing()
    {

        $keyEncryptionAlgorithmManager = JWAManager::create([new RSAOAEP256()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE($this->getKeyToEncrypt());
        $jwe = $jwe->withSharedProtectedHeaders([
            'kid' => '123456789',
            'alg' => 'RSA-OAEP-256',
            'zip' => 'DEF',
        ]);
        $jwe = $jwe->addRecipientInformation(
            $this->getRSARecipientKey()
        );

        $encrypter->encrypt($jwe);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The key encryption algorithm "A256CBC-HS512" is not supported or not a key encryption algorithm instance.
     */
    public function testNotAKeyEncryptionAlgorithm()
    {

        $keyEncryptionAlgorithmManager = JWAManager::create([new A256CBCHS512()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256CBCHS512()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE($this->getKeyToEncrypt());
        $jwe = $jwe->withSharedProtectedHeaders([
            'kid' => '123456789',
            'enc' => 'A256CBC-HS512',
            'alg' => 'A256CBC-HS512',
            'zip' => 'DEF',
        ]);
        $jwe = $jwe->addRecipientInformation(
            $this->getRSARecipientKey()
        );

        $encrypter->encrypt($jwe);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The content encryption algorithm "RSA-OAEP-256" is not supported or not a content encryption algorithm instance.
     */
    public function testNotAContentEncryptionAlgorithm()
    {

        $keyEncryptionAlgorithmManager = JWAManager::create([new RSAOAEP256()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new RSAOAEP256()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE($this->getKeyToEncrypt());
        $jwe = $jwe->withSharedProtectedHeaders([
            'kid' => '123456789',
            'enc' => 'RSA-OAEP-256',
            'alg' => 'RSA-OAEP-256',
            'zip' => 'DEF',
        ]);

        $jwe = $jwe->addRecipientInformation(
            $this->getRSARecipientKey()
        );

        $encrypter->encrypt($jwe);
    }

    public function testEncryptAndLoadCompactWithDirectKeyEncryption()
    {
        $keyEncryptionAlgorithmManager = JWAManager::create([new Dir()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A192CBCHS384()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE($this->getKeyToEncrypt());
        $jwe = $jwe->withSharedProtectedHeaders([
            'kid' => 'DIR_1',
            'enc' => 'A192CBC-HS384',
            'alg' => 'dir',
        ]);

        $jwe = $jwe->addRecipientInformation(
            $this->getDirectKey()
        );
        $encrypter->encrypt($jwe);

        $encrypted = $jwe->toFlattenedJSON(0);

        $loader = new Loader();
        $loaded = $loader->load($encrypted);

        $this->assertInstanceOf(JWE::class, $loaded);
        $this->assertEquals('dir', $loaded->getSharedProtectedHeader('alg'));
        $this->assertEquals('A192CBC-HS384', $loaded->getSharedProtectedHeader('enc'));
        $this->assertFalse($loaded->hasSharedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getSymmetricKeySet(), $index);

        $this->assertEquals(0, $index);
        $this->assertTrue(is_array($loaded->getPayload()));
        $this->assertEquals($this->getKeyToEncrypt(), new JWK($loaded->getPayload()));
    }

    public function testEncryptAndLoadCompactKeyAgreement()
    {
        $keyEncryptionAlgorithmManager = JWAManager::create([new ECDHES()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A192CBCHS384()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE(['user_id' => '1234', 'exp' => time() + 3600]);
        $jwe = $jwe->withSharedProtectedHeaders([
            'kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d',
            'enc' => 'A192CBC-HS384',
            'alg' => 'ECDH-ES',
        ]);

        $jwe = $jwe->addRecipientInformation(
            $this->getECDHRecipientPublicKey()
        );

        $encrypter->encrypt($jwe);

        $loader = new Loader();
        $loaded = $loader->load($jwe->toFlattenedJSON(0));

        $this->assertInstanceOf(JWE::class, $loaded);
        $this->assertEquals('ECDH-ES', $loaded->getSharedProtectedHeader('alg'));
        $this->assertEquals('A192CBC-HS384', $loaded->getSharedProtectedHeader('enc'));
        $this->assertFalse($loaded->hasSharedProtectedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        $this->assertEquals(0, $index);
        $this->assertTrue($loaded->hasClaims());
        $this->assertTrue($loaded->hasClaim('user_id'));
        $this->assertEquals('1234', $loaded->getClaim('user_id'));
    }

    public function testEncryptAndLoadCompactKeyAgreementWithWrappingCompact()
    {
        $keyEncryptionAlgorithmManager = JWAManager::create([new ECDHESA256KW()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256CBCHS512()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE('Live long and Prosper.');
        $jwe = $jwe->withSharedProtectedHeaders([
            'kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d',
            'enc' => 'A256CBC-HS512',
            'alg' => 'ECDH-ES+A256KW',
        ]);

        $jwe = $jwe->addRecipientInformation(
            $this->getECDHRecipientPublicKey()
        );

        $encrypter->encrypt($jwe);

        $loader = new Loader();
        $loaded = $loader->load($jwe->toFlattenedJSON(0));

        $this->assertInstanceOf(JWE::class, $loaded);
        $this->assertEquals('ECDH-ES+A256KW', $loaded->getSharedProtectedHeader('alg'));
        $this->assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        $this->assertFalse($loaded->hasSharedProtectedHeader('zip'));
        $this->assertFalse($loaded->hasSharedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        $this->assertEquals(0, $index);
        $this->assertTrue(is_string($loaded->getPayload()));
        $this->assertEquals('Live long and Prosper.', $loaded->getPayload());
    }

    public function testEncryptAndLoadWithGCMAndAAD()
    {

        $keyEncryptionAlgorithmManager = JWAManager::create([new ECDHESA256KW()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256GCM()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE(
            'Live long and Prosper.',
            [
                'kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d',
                'enc' => 'A256GCM',
                'alg' => 'ECDH-ES+A256KW',
            ],
            [],
            'foo,bar,baz'
        );

        $jwe = $jwe->addRecipientInformation(
            $this->getECDHRecipientPublicKey()
        );

        $encrypter->encrypt($jwe);

        $loader = new Loader();
        $loaded = $loader->load($jwe->toFlattenedJSON(0));

        $keyEncryptionAlgorithmManager = JWAManager::create([new ECDHESA256KW()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256GCM()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $this->assertInstanceOf(JWE::class, $loaded);
        $this->assertEquals('ECDH-ES+A256KW', $loaded->getSharedProtectedHeader('alg'));
        $this->assertEquals('A256GCM', $loaded->getSharedProtectedHeader('enc'));
        $this->assertFalse($loaded->hasSharedProtectedHeader('zip'));
        $this->assertFalse($loaded->hasSharedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        $this->assertEquals(0, $index);
        $this->assertTrue(is_string($loaded->getPayload()));
        $this->assertEquals('Live long and Prosper.', $loaded->getPayload());
    }

    public function testEncryptAndLoadCompactKeyAgreementWithWrapping()
    {
        $keyEncryptionAlgorithmManager = JWAManager::create([new RSAOAEP256(), new ECDHESA256KW()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A256CBCHS512()]);
        $compressionManager = CompressionManager::create([new Deflate()]);
        $encrypter = new Encrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = JWEFactory::createJWE('Live long and Prosper.');
        $jwe = $jwe->withSharedProtectedHeaders(['enc' => 'A256CBC-HS512']);

        $jwe = $jwe->addRecipientInformation(
            $this->getECDHRecipientPublicKey(),
            ['kid' => 'e9bc097a-ce51-4036-9562-d2ade882db0d', 'alg' => 'ECDH-ES+A256KW']
        );
        $jwe = $jwe->addRecipientInformation(
            $this->getRSARecipientKey(),
            ['kid' => '123456789', 'alg' => 'RSA-OAEP-256']
        );

        $encrypter->encrypt($jwe);

        $loader = new Loader();
        $loaded = $loader->load($jwe->toJSON());

        $this->assertEquals(2, $loaded->countRecipients());

        $this->assertInstanceOf(JWE::class, $loaded);
        $this->assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        $this->assertEquals('ECDH-ES+A256KW', $loaded->getRecipient(0)->getHeader('alg'));
        $this->assertEquals('RSA-OAEP-256', $loaded->getRecipient(1)->getHeader('alg'));
        $this->assertFalse($loaded->hasSharedHeader('zip'));
        $this->assertFalse($loaded->hasSharedProtectedHeader('zip'));
        $this->assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        $this->assertEquals(0, $index);
        $this->assertTrue(is_string($loaded->getPayload()));
        $this->assertEquals('Live long and Prosper.', $loaded->getPayload());
    }

    /**
     * @return JWK
     */
    private function getKeyToEncrypt()
    {
        $key = new JWK([
            'kty' => 'EC',
            'use' => 'enc',
            'crv' => 'P-256',
            'x'   => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'   => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd'   => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);

        return $key;
    }

    /**
     * @return JWKSet
     */
    private function getKeySetToEncrypt()
    {
        $key = new JWK([
            'kty' => 'EC',
            'use' => 'enc',
            'crv' => 'P-256',
            'x'   => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'   => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd'   => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);

        $key_set = new JWKSet();
        $key_set->addKey($key);

        return $key_set;
    }

    /**
     * @return JWK
     */
    private function getRSARecipientKey()
    {
        $key = new JWK([
            'kty' => 'RSA',
            'use' => 'enc',
            'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e'   => 'AQAB',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    private function getRSARecipientKeyWithAlgorithm()
    {
        $key = new JWK([
            'kty' => 'RSA',
            'use' => 'enc',
            'alg' => 'RSA-OAEP',
            'n'   => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e'   => 'AQAB',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    private function getSigningKey()
    {
        $key = new JWK([
            'kty'     => 'EC',
            'key_ops' => ['sign', 'verify'],
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd'       => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    private function getECDHRecipientPublicKey()
    {
        $key = new JWK([
            'kty'     => 'EC',
            'key_ops' => ['encrypt', 'decrypt'],
            'crv'     => 'P-256',
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    private function getDirectKey()
    {
        $key = new JWK([
            'kid'     => 'DIR_1',
            'key_ops' => ['encrypt', 'decrypt'],
            'kty'     => 'oct',
            'k'       => Base64Url::encode(hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F')),
        ]);

        return $key;
    }
}
