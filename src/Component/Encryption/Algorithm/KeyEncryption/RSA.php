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

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Assert\Assertion;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Util\RSA as JoseRSA;
use Jose\Component\KeyManagement\KeyConverter\RSAKey;

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
    public function encryptKey(JWK $key, string $cek, array $complete_headers, array &$additional_headers): string
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
    public function decryptKey(JWK $key, string $encrypted_cek, array $header): string
    {
        $this->checkKey($key);
        Assertion::true($key->has('d'), 'The key is not a private key');

        $priv = new RSAKey($key);

        if (self::ENCRYPTION_OAEP === $this->getEncryptionMode()) {
            $decrypted = JoseRSA::decrypt($priv, $encrypted_cek, $this->getHashAlgorithm());
            Assertion::string($decrypted, 'Unable to decrypt the data.');

            return $decrypted;
        } else {
            $res = openssl_private_decrypt($encrypted_cek, $decrypted, $priv->toPEM(), OPENSSL_PKCS1_PADDING | OPENSSL_RAW_DATA);
            Assertion::true($res, 'Unable to decrypt the data.');

            return $decrypted;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyManagementMode(): string
    {
        return self::MODE_ENCRYPT;
    }

    /**
     * @param JWK $key
     */
    protected function checkKey(JWK $key)
    {
        Assertion::eq($key->get('kty'), 'RSA', 'Wrong key type.');
    }

    /**
     * @return int
     */
    abstract protected function getEncryptionMode(): int;

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm(): string;
}
