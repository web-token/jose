<?php

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
use Base64Url\Base64Url;
use Jose\Component\Core\JWK;

final class Dir implements DirectEncryptionInterface
{
    /**
     * {@inheritdoc}
     */
    public function getCEK(JWK $key): string
    {
        Assertion::eq($key->get('kty'), 'oct', 'Wrong key type.');
        Assertion::true($key->has('k'), 'The key parameter "k" is missing.');

        return Base64Url::decode($key->get('k'));
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'dir';
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyManagementMode(): string
    {
        return self::MODE_DIRECT;
    }
}
