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

use AESGCM\AESGCM;
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
    public function wrapKey(JWKInterface $key, $cek, array $complete_headers, array &$additional_headers)
    {
        $this->checkKey($key);
        $kek = Base64Url::decode($key->get('k'));
        $iv = random_bytes(96 / 8);
        $additional_headers['iv'] = Base64Url::encode($iv);

        list($encrypted_cek, $tag) = AESGCM::encrypt($kek, $iv, $cek, null);
        $additional_headers['tag'] = Base64Url::encode($tag);

        return $encrypted_cek;
    }

    /**
     * {@inheritdoc}
     */
    public function unwrapKey(JWKInterface $key, $encrypted_cek, array $header)
    {
        $this->checkKey($key);
        $this->checkAdditionalParameters($header);

        $kek = Base64Url::decode($key->get('k'));
        $tag = Base64Url::decode($header['tag']);
        $iv = Base64Url::decode($header['iv']);

        return AESGCM::decrypt($kek, $iv, $encrypted_cek, null, $tag);
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyManagementMode()
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
    abstract protected function getKeySize();
}
