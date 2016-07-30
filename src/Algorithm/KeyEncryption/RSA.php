<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\KeyEncryption;

use Assert\Assertion;
use Jose\KeyConverter\RSAKey;
use Jose\Object\JWKInterface;
use Jose\Util\RSA as JoseRSA;

/**
 * Class RSA.
 */
abstract class RSA implements KeyEncryptionInterface
{
    /**
     * Optimal Asymmetric Encryption Padding (OAEP).
     */
    const ENCRYPTION_OAEP = 1;

    /**
     * Use PKCS#1 padding.
     */
    const ENCRYPTION_PKCS1 = 2;

    /**
     * {@inheritdoc}
     */
    public function encryptKey(JWKInterface $key, $cek, array $complete_headers, array &$additional_headers)
    {
        $this->checkKey($key);

        $pub = RSAKey::toPublic(new RSAKey($key));

        if (self::ENCRYPTION_OAEP === $this->getEncryptionMode()) {
            $encrypted = JoseRSA::encrypt($pub, $cek, $this->getHashAlgorithm());
            Assertion::string($encrypted, 'Unable to encrypt the data.');

            return $encrypted;
        } else {
            $res = openssl_public_encrypt($cek, $encrypted, $pub->toPEM(), OPENSSL_PKCS1_PADDING | OPENSSL_RAW_DATA);
            Assertion::true($res, 'Unable to encrypt the data.');

            return $encrypted;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function decryptKey(JWKInterface $key, $encrypted_key, array $header)
    {
        $this->checkKey($key);
        Assertion::true($key->has('d'), 'The key is not a private key');

        $priv = new RSAKey($key);

        if (self::ENCRYPTION_OAEP === $this->getEncryptionMode()) {
            $decrypted = JoseRSA::decrypt($priv, $encrypted_key, $this->getHashAlgorithm());
            Assertion::string($decrypted, 'Unable to decrypt the data.');

            return $decrypted;
        } else {
            $res = openssl_private_decrypt($encrypted_key, $decrypted, $priv->toPEM(), OPENSSL_PKCS1_PADDING | OPENSSL_RAW_DATA);
            Assertion::true($res, 'Unable to decrypt the data.');

            return $decrypted;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyManagementMode()
    {
        return self::MODE_ENCRYPT;
    }

    /**
     * @param JWKInterface $key
     */
    protected function checkKey(JWKInterface $key)
    {
        Assertion::eq($key->get('kty'), 'RSA', 'Wrong key type.');
    }

    /**
     * @return int
     */
    abstract protected function getEncryptionMode();

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm();
}
