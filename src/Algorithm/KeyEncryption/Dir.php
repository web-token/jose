<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\KeyEncryption;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Object\JWKInterface;

final class Dir implements DirectEncryptionInterface
{
    /**
     * {@inheritdoc}
     */
    public function getCEK(JWKInterface $key)
    {
        Assertion::eq($key->get('kty'), 'oct', 'Wrong key type.');
        Assertion::true($key->has('k'), 'The key parameter "k" is missing.');

        return Base64Url::decode($key->get('k'));
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithmName()
    {
        return 'dir';
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyManagementMode()
    {
        return self::MODE_DIRECT;
    }
}
