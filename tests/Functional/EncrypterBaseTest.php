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
use Jose\Decrypter;
use Jose\Encrypter;
use Jose\Factory\JWEFactory;
use Jose\Loader;
use Jose\Object\JWEInterface;
use Jose\Object\JWK;
use Jose\Object\JWKSet;
use Jose\Test\Stub\FakeLogger;
use Jose\Test\BaseTestCase;

/**
 * Class EncrypterTest.
 *
 * @group Encrypter
 * @group Functional
 */
class EncrypterBaseTest extends BaseTestCase
{
    public function testEncryptWithJWTInput()
    {
        $encrypter = Encrypter::createEncrypter(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());
        $decrypter = Decrypter::createDecrypter(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());

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

        $loader = new Loader(new FakeLogger());
        $loaded = $loader->load($encrypted);

        self::assertInstanceOf(JWEInterface::class, $loaded);
        self::assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeader('alg'));
        self::assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        self::assertEquals('DEF', $loaded->getSharedProtectedHeader('zip'));
        self::assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        self::assertEquals(0, $index);
        self::assertEquals('FOO', $loaded->getPayload());
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

        $loader = new Loader(new FakeLogger());
        $loaded = $loader->load($jwe);

        self::assertInstanceOf(JWEInterface::class, $loaded);
        self::assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeader('alg'));
        self::assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        self::assertEquals('DEF', $loaded->getSharedProtectedHeader('zip'));
        self::assertNull($loaded->getPayload());

        $decrypter = Decrypter::createDecrypter(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());
        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        self::assertEquals(0, $index);
        self::assertEquals('FOO', $loaded->getPayload());
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

        $loader = new Loader(new FakeLogger());
        $loaded = $loader->load($jwe);

        self::assertInstanceOf(JWEInterface::class, $loaded);
        self::assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeader('alg'));
        self::assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        self::assertEquals('DEF', $loaded->getSharedProtectedHeader('zip'));
        self::assertEquals('bar', $loaded->getSharedHeader('foo'));
        self::assertEquals('A,B,C,D', $loaded->getAAD('foo'));
        self::assertEquals('ploc', $loaded->getRecipient(0)->getHeader('plic'));
        self::assertNull($loaded->getPayload());

        $decrypter = Decrypter::createDecrypter(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());
        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        self::assertEquals(0, $index);
        self::assertEquals('FOO', $loaded->getPayload());
    }

    public function testEncryptAndLoadFlattenedWithAAD()
    {
        $encrypter = Encrypter::createEncrypter(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());
        $decrypter = Decrypter::createDecrypter(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());

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

        $loader = new Loader(new FakeLogger());
        $loaded = $loader->load($encrypted);

        self::assertInstanceOf(JWEInterface::class, $loaded);
        self::assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeader('alg'));
        self::assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        self::assertEquals('DEF', $loaded->getSharedProtectedHeader('zip'));
        self::assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        self::assertEquals(0, $index);
        self::assertTrue(is_array($loaded->getPayload()));
        self::assertEquals($this->getKeyToEncrypt(), new JWK($loaded->getPayload()));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Compression method "FIP" not supported
     */
    public function testCompressionAlgorithmNotSupported()
    {
        $encrypter = Encrypter::createEncrypter(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());

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
        $encrypter = Encrypter::createEncrypter(['RSA-OAEP', 'RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());

        $jwe = JWEFactory::createJWE('Live long and Prosper.');
        $jwe = $jwe->withSharedProtectedHeaders([
            'enc' => 'A256CBC-HS512',
        ]);

        $jwe = $jwe->addRecipientInformation($this->getRSARecipientKeyWithAlgorithm(), ['alg' => 'RSA-OAEP']);
        $jwe = $jwe->addRecipientInformation($this->getRSARecipientKey(), ['alg' => 'RSA-OAEP-256']);

        $encrypter->encrypt($jwe);

        self::assertEquals(2, $jwe->countRecipients());
    }

    public function testMultipleInstructionsNotAllowedWithFlattenedSerialization()
    {
        $encrypter = Encrypter::createEncrypter(['RSA-OAEP-256', 'ECDH-ES+A256KW'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());

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

        self::assertEquals(2, $jwe->countRecipients());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Foreign key management mode forbidden.
     */
    public function testForeignKeyManagementModeForbidden()
    {
        $encrypter = Encrypter::createEncrypter(['dir', 'ECDH-ES+A256KW'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());

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
        $encrypter = Encrypter::createEncrypter(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());

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
        $encrypter = Encrypter::createEncrypter(['RSA-OAEP-256'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());

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
        $encrypter = Encrypter::createEncrypter(['RSA-OAEP-256'], ['A128CBC-HS256'], ['DEF'], new FakeLogger());
        $decrypter = Decrypter::createDecrypter(['RSA-OAEP-256'], ['A128CBC-HS256'], ['DEF'], new FakeLogger());

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

        $loader = new Loader(new FakeLogger());
        $loaded = $loader->load($encrypted);

        self::assertInstanceOf(JWEInterface::class, $loaded);
        self::assertEquals('RSA-OAEP-256', $loaded->getSharedProtectedHeader('alg'));
        self::assertEquals('A128CBC-HS256', $loaded->getSharedProtectedHeader('enc'));
        self::assertEquals('DEF', $loaded->getSharedProtectedHeader('zip'));
        self::assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        self::assertEquals(0, $index);
        self::assertTrue(is_array($loaded->getPayload()));
        self::assertEquals($this->getKeySetToEncrypt(), new JWKSet($loaded->getPayload()));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Parameter "alg" is missing.
     */
    public function testAlgParameterIsMissing()
    {
        $encrypter = Encrypter::createEncrypter(['A256CBC-HS512'], [], ['DEF'], new FakeLogger());

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
        $encrypter = Encrypter::createEncrypter(['RSA-OAEP-256'], [], ['DEF'], new FakeLogger());

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
        $encrypter = Encrypter::createEncrypter(['A256CBC-HS512'], [], ['DEF'], new FakeLogger());

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
        $encrypter = Encrypter::createEncrypter(['RSA-OAEP-256'], [], ['DEF'], new FakeLogger());

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
        $encrypter = Encrypter::createEncrypter(['dir'], ['A192CBC-HS384'], ['DEF'], new FakeLogger());
        $decrypter = Decrypter::createDecrypter(['dir'], ['A192CBC-HS384'], ['DEF'], new FakeLogger());

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

        $loader = new Loader(new FakeLogger());
        $loaded = $loader->load($encrypted);

        self::assertInstanceOf(JWEInterface::class, $loaded);
        self::assertEquals('dir', $loaded->getSharedProtectedHeader('alg'));
        self::assertEquals('A192CBC-HS384', $loaded->getSharedProtectedHeader('enc'));
        self::assertFalse($loaded->hasSharedHeader('zip'));
        self::assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getSymmetricKeySet(), $index);

        self::assertEquals(0, $index);
        self::assertTrue(is_array($loaded->getPayload()));
        self::assertEquals($this->getKeyToEncrypt(), new JWK($loaded->getPayload()));
    }

    public function testEncryptAndLoadCompactKeyAgreement()
    {
        $encrypter = Encrypter::createEncrypter(['ECDH-ES'], ['A192CBC-HS384'], ['DEF'], new FakeLogger());
        $decrypter = Decrypter::createDecrypter(['ECDH-ES'], ['A192CBC-HS384'], ['DEF'], new FakeLogger());

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

        $loader = new Loader(new FakeLogger());
        $loaded = $loader->load($jwe->toFlattenedJSON(0));

        self::assertInstanceOf(JWEInterface::class, $loaded);
        self::assertEquals('ECDH-ES', $loaded->getSharedProtectedHeader('alg'));
        self::assertEquals('A192CBC-HS384', $loaded->getSharedProtectedHeader('enc'));
        self::assertFalse($loaded->hasSharedProtectedHeader('zip'));
        self::assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        self::assertEquals(0, $index);
        self::assertTrue($loaded->hasClaims());
        self::assertTrue($loaded->hasClaim('user_id'));
        self::assertEquals('1234', $loaded->getClaim('user_id'));
    }

    public function testEncryptAndLoadCompactKeyAgreementWithWrappingCompact()
    {
        $encrypter = Encrypter::createEncrypter(['ECDH-ES+A256KW'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());
        $decrypter = Decrypter::createDecrypter(['ECDH-ES+A256KW'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());

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

        $loader = new Loader(new FakeLogger());
        $loaded = $loader->load($jwe->toFlattenedJSON(0));

        self::assertInstanceOf(JWEInterface::class, $loaded);
        self::assertEquals('ECDH-ES+A256KW', $loaded->getSharedProtectedHeader('alg'));
        self::assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        self::assertFalse($loaded->hasSharedProtectedHeader('zip'));
        self::assertFalse($loaded->hasSharedHeader('zip'));
        self::assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        self::assertEquals(0, $index);
        self::assertTrue(is_string($loaded->getPayload()));
        self::assertEquals('Live long and Prosper.', $loaded->getPayload());
    }

    public function testEncryptAndLoadWithGCMAndAAD()
    {
        $encrypter = Encrypter::createEncrypter(['ECDH-ES+A256KW'], ['A256GCM'], ['DEF'], new FakeLogger());

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

        $loader = new Loader(new FakeLogger());
        $loaded = $loader->load($jwe->toFlattenedJSON(0));

        $decrypter = Decrypter::createDecrypter(['A256GCM'], ['ECDH-ES+A256KW'], ['DEF'], new FakeLogger());

        self::assertInstanceOf(JWEInterface::class, $loaded);
        self::assertEquals('ECDH-ES+A256KW', $loaded->getSharedProtectedHeader('alg'));
        self::assertEquals('A256GCM', $loaded->getSharedProtectedHeader('enc'));
        self::assertFalse($loaded->hasSharedProtectedHeader('zip'));
        self::assertFalse($loaded->hasSharedHeader('zip'));
        self::assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        self::assertEquals(0, $index);
        self::assertTrue(is_string($loaded->getPayload()));
        self::assertEquals('Live long and Prosper.', $loaded->getPayload());
    }

    public function testEncryptAndLoadCompactKeyAgreementWithWrapping()
    {
        $encrypter = Encrypter::createEncrypter(['RSA-OAEP-256', 'ECDH-ES+A256KW'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());
        $decrypter = Decrypter::createDecrypter(['RSA-OAEP-256', 'ECDH-ES+A256KW'], ['A256CBC-HS512'], ['DEF'], new FakeLogger());

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

        $loader = new Loader(new FakeLogger());
        $loaded = $loader->load($jwe->toJSON());

        self::assertEquals(2, $loaded->countRecipients());

        self::assertInstanceOf(JWEInterface::class, $loaded);
        self::assertEquals('A256CBC-HS512', $loaded->getSharedProtectedHeader('enc'));
        self::assertEquals('ECDH-ES+A256KW', $loaded->getRecipient(0)->getHeader('alg'));
        self::assertEquals('RSA-OAEP-256', $loaded->getRecipient(1)->getHeader('alg'));
        self::assertFalse($loaded->hasSharedHeader('zip'));
        self::assertFalse($loaded->hasSharedProtectedHeader('zip'));
        self::assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getPrivateKeySet(), $index);

        self::assertEquals(0, $index);
        self::assertTrue(is_string($loaded->getPayload()));
        self::assertEquals('Live long and Prosper.', $loaded->getPayload());
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
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
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
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
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
            'n' => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e' => 'AQAB',
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
            'n' => 'tpS1ZmfVKVP5KofIhMBP0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0S-I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0_5rQCpcEt_Dn5iM-BNn7fqpoLIbks8rXKUIj8-qMVqkTXsEKeKinE23t1ykMldsNaaOH-hvGti5Jt2DMnH1JjoXdDXfxvSP_0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY_Cp7J4Mn1ejZ6HNmyvoTE_4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJsw',
            'e' => 'AQAB',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    private function getSigningKey()
    {
        $key = new JWK([
            'kty' => 'EC',
            'key_ops' => ['sign', 'verify'],
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    private function getECDHRecipientPublicKey()
    {
        $key = new JWK([
            'kty' => 'EC',
            'key_ops' => ['encrypt', 'decrypt'],
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]);

        return $key;
    }

    /**
     * @return JWK
     */
    private function getDirectKey()
    {
        $key = new JWK([
            'kid' => 'DIR_1',
            'key_ops' => ['encrypt', 'decrypt'],
            'kty' => 'oct',
            'k' => Base64Url::encode(hex2bin('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F')),
        ]);

        return $key;
    }
}
