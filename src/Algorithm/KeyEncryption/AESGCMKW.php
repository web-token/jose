<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\KeyEncryption;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Object\JWKInterface;

/**
 * Class AESGCMKW.
 */
abstract class AESGCMKW implements KeyWrappingInterface
{
    /**
     * {@inheritdoc}
     */
    public function wrapKey(JWKInterface $key, string $cek, array $complete_headers, array &$additional_headers): string
    {
        $this->checkKey($key);
        $kek = Base64Url::decode($key->get('k'));
        $iv = random_bytes(96 / 8);
        $additional_headers['iv'] = Base64Url::encode($iv);

        $key_length = mb_strlen($kek, '8bit') * 8;
        $mode = 'aes-'.($key_length).'-gcm';
        $tag = null;
        $encrypted_cek = openssl_encrypt($cek, $mode, $kek, OPENSSL_RAW_DATA, $iv, $tag, null);
        Assertion::true(false !== $encrypted_cek, 'Unable to encrypt the data.');

        //list($encrypted_cek, $tag) = AESGCM::encrypt($kek, $iv, $cek, null);
        $additional_headers['tag'] = Base64Url::encode($tag);

        return $encrypted_cek;
    }

    /**
     * {@inheritdoc}
     */
    public function unwrapKey(JWKInterface $key, string $encrypted_cek, array $complete_headers): string
    {
        $this->checkKey($key);
        $this->checkAdditionalParameters($complete_headers);

        $kek = Base64Url::decode($key->get('k'));
        $tag = Base64Url::decode($complete_headers['tag']);
        $iv = Base64Url::decode($complete_headers['iv']);

        $key_length = mb_strlen($kek, '8bit') * 8;

        $mode = sprintf('aes-%d-gcm', $key_length);
        $cek = openssl_decrypt($encrypted_cek, $mode, $kek, OPENSSL_RAW_DATA, $iv, $tag, null);
        Assertion::true(false !== $cek, 'Unable to decrypt or to verify the tag.');

        return $cek;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyManagementMode(): string
    {
        return self::MODE_WRAP;
    }

    /**
     * @param JWKInterface $key
     */
    protected function checkKey(JWKInterface $key)
    {
        Assertion::eq($key->get('kty'), 'oct', 'Wrong key type.');
        Assertion::true($key->has('k'), 'The key parameter "k" is missing.');
    }

    /**
     * @param array $header
     */
    protected function checkAdditionalParameters(array $header)
    {
        Assertion::keyExists($header, 'iv', 'Parameter "iv" is missing.');
        Assertion::keyExists($header, 'tag', 'Parameter "tag" is missing.');
    }

    /**
     * @return int
     */
    abstract protected function getKeySize(): int;
}
