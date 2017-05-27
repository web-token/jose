<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Util;

use Base64Url\Base64Url;
use Jose\Object\JWE;

final class JWELoader
{
    /**
     * @param array $data
     *
     * @return JWE
     */
    public static function loadSerializedJsonJWE(array $data): JWE
    {
        $jwe = new JWE();
        $jwe = $jwe->withCiphertext(Base64Url::decode($data['ciphertext']));

        self::populateIV($jwe, $data);
        self::populateAAD($jwe, $data);
        self::populateTag($jwe, $data);
        self::populateSharedProtectedHeaders($jwe, $data);
        self::populateSharedHeaders($jwe, $data);

        foreach ($data['recipients'] as $recipient) {
            $encrypted_key = self::getRecipientEncryptedKey($recipient);
            $recipient_headers = self::getRecipientHeaders($recipient);

            $jwe = $jwe->addRecipientWithEncryptedKey($encrypted_key, $recipient_headers);
        }

        return $jwe;
    }

    /**
     * @param JWE $jwe
     * @param array                     $data
     */
    private static function populateIV(JWE &$jwe, array $data)
    {
        if (array_key_exists('iv', $data)) {
            $jwe = $jwe->withIV(Base64Url::decode($data['iv']));
        }
    }

    /**
     * @param JWE $jwe
     * @param array                     $data
     */
    private static function populateAAD(JWE &$jwe, array $data)
    {
        if (array_key_exists('aad', $data)) {
            $jwe = $jwe->withAAD(Base64Url::decode($data['aad']));
        }
    }

    /**
     * @param JWE $jwe
     * @param array                     $data
     */
    private static function populateTag(JWE &$jwe, array $data)
    {
        if (array_key_exists('tag', $data)) {
            $jwe = $jwe->withTag(Base64Url::decode($data['tag']));
        }
    }

    /**
     * @param JWE $jwe
     * @param array                     $data
     */
    private static function populateSharedProtectedHeaders(JWE &$jwe, array $data)
    {
        if (array_key_exists('protected', $data)) {
            $jwe = $jwe->withEncodedSharedProtectedHeaders($data['protected']);
            $jwe = $jwe->withSharedProtectedHeaders(json_decode(Base64Url::decode($data['protected']), true));
        }
    }

    /**
     * @param JWE $jwe
     * @param array                     $data
     */
    private static function populateSharedHeaders(JWE &$jwe, array $data)
    {
        if (array_key_exists('unprotected', $data)) {
            $jwe = $jwe->withSharedHeaders($data['unprotected']);
        }
    }

    /**
     * @param array $data
     *
     * @return array
     */
    private static function getRecipientHeaders(array $data): array
    {
        if (array_key_exists('header', $data)) {
            return $data['header'];
        }

        return [];
    }

    /**
     * @param array $data
     *
     * @return null|string
     */
    private static function getRecipientEncryptedKey(array $data): ?string
    {
        if (array_key_exists('encrypted_key', $data)) {
            return Base64Url::decode($data['encrypted_key']);
        }

        return null;
    }
}
