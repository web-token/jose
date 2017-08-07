<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Performance\JWE;

use Jose\Component\Core\JWAManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\KeyEncryption;
use Jose\Component\Encryption\Algorithm\ContentEncryption;
use Jose\Component\Encryption\Compression;
use Jose\Component\Encryption\Compression\CompressionMethodsManager;
use Jose\Component\Encryption\JWEBuilder;

/**
 * @BeforeMethods({"init"})
 * @Groups({"JWE"})
 * @Revs(100)
 */
abstract class EncryptionBench
{
    private $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
    /**
     * @param JWAManager
     */
    private $contentEncryptionAlgorithmsManager;

    /**
     * @param JWAManager
     */
    private $keyEncryptionAlgorithmsManager;

    /**
     * @param CompressionManager
     */
    private $compressionMethodsManager;

    public function init()
    {
        $this->keyEncryptionAlgorithmsManager = JWAManager::create([
            new KeyEncryption\A128KW(),
            new KeyEncryption\A192KW(),
            new KeyEncryption\A256KW(),
            new KeyEncryption\A128GCMKW(),
            new KeyEncryption\A192GCMKW(),
            new KeyEncryption\A256GCMKW(),
            new KeyEncryption\Dir(),
            new KeyEncryption\ECDHES(),
            new KeyEncryption\ECDHESA128KW(),
            new KeyEncryption\ECDHESA192KW(),
            new KeyEncryption\ECDHESA256KW(),
            new KeyEncryption\PBES2HS256A128KW(),
            new KeyEncryption\PBES2HS384A192KW(),
            new KeyEncryption\PBES2HS512A256KW(),
            new KeyEncryption\RSA15(),
            new KeyEncryption\RSAOAEP(),
            new KeyEncryption\RSAOAEP256(),
        ]);

        $this->contentEncryptionAlgorithmsManager = JWAManager::create([
            new ContentEncryption\A128CBCHS256(),
            new ContentEncryption\A192CBCHS384(),
            new ContentEncryption\A256CBCHS512(),
            new ContentEncryption\A128GCM(),
            new ContentEncryption\A192GCM(),
            new ContentEncryption\A256GCM(),
        ]);

        $this->compressionMethodsManager = CompressionMethodsManager::create([
            new Compression\Deflate(),
            new Compression\GZip(),
            new Compression\ZLib(),
        ]);
    }

    /**
     * @ParamProviders({"dataHeadersAndAlgorithms"})
     */
    public function benchEncryption($params)
    {
        $jweBuilder = new JWEBuilder(
            $this->getKeyEncryptionAlgorithmsManager(),
            $this->getContentEncryptionAlgorithmsManager(),
            $this->getCompressionMethodsManager()
        );
        $jweBuilder
            ->withPayload($this->payload)
            ->withAAD($this->getAAD())
            ->withSharedProtectedHeaders($params['data']['shared_protected_headers'])
            ->withSharedHeaders($params['data']['shared_headers'])
            ->addRecipient($this->getRecipientPublicKey(), $params['data']['recipient_headers'])
            ->build()
            ->toFlattenedJSON(0);
    }

    public function benchDecryption()
    {
        /*$jws = JWSLoader::load($params['input']);
        $verifier = new Verifier($this->jwaManager);
        $verifier->verifyWithKey($jws, $this->getPublicKey(), null, $index);*/
    }

    /**
     * @return null|string
     */
    abstract protected function getAAD(): ?string;

    /**
     * @return JWK
     */
    abstract protected function getRecipientPrivateKey(): JWK;

    /**
     * @return JWK
     */
    abstract protected function getRecipientPublicKey(): JWK;

    /**
     * @return JWAManager
     */
    private function getKeyEncryptionAlgorithmsManager(): JWAManager
    {
        return $this->keyEncryptionAlgorithmsManager;
    }

    /**
     * @return JWAManager
     */
    private function getContentEncryptionAlgorithmsManager(): JWAManager
    {
        return $this->contentEncryptionAlgorithmsManager;
    }

    /**
     * @return CompressionMethodsManager
     */
    private function getCompressionMethodsManager(): CompressionMethodsManager
    {
        return $this->compressionMethodsManager;
    }
}
