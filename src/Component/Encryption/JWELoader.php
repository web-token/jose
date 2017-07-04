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

namespace Jose\Component\Encryption;

use Base64Url\Base64Url;

/**
 * Class able to load JWS or JWE.
 * JWS object can also be verified.
 */
final class JWELoader
{
    /**
     * Load data and try to return a JWS object, a JWE object or a list of these objects.
     * If the result is a JWE (list), nothing is decrypted and method `decrypt` must be executed
     * If the result is a JWS (list), no signature is verified and method `verifySignature` must be executed.
     *
     * @param string $input A string that represents a JSON Web Token message
     *
     * @return JWE if the data has been loaded
     */
    public static function load(string $input): JWE
    {
        $json = self::convert($input);

        return self::loadSerializedJsonJWE($json);
    }

    /**
     * @param string $input
     *
     * @return array
     */
    private static function convert(string $input): array
    {
        if (is_array($data = json_decode($input, true))) {
            if (array_key_exists('recipients', $data)) {
                return $data;
            } elseif (array_key_exists('ciphertext', $data)) {
                return self::fromFlattenedSerializationRecipientToSerialization($data);
            }
        } elseif (is_string($input)) {
            return self::fromCompactSerializationToSerialization($input);
        }
        throw new \InvalidArgumentException('Unsupported input');
    }

    /**
     * @param array $input
     *
     * @return array
     */
    private static function fromFlattenedSerializationRecipientToSerialization(array $input): array
    {
        $recipient = [];
        $recipient = array_merge(
            $recipient,
            array_intersect_key($input, array_flip(['header', 'encrypted_key']))
        );
        $recipients = [
            'ciphertext' => $input['ciphertext'],
            'recipients' => [$recipient],
        ];
        $recipients = array_merge(
            $recipients,
            array_intersect_key($input, array_flip(['protected', 'unprotected', 'iv', 'aad', 'tag']))
        );

        return $recipients;
    }

    /**
     * @param string $input
     *
     * @return array
     */
    private static function fromCompactSerializationToSerialization(string $input): array
    {
        $parts = explode('.', $input);
        switch (count($parts)) {
            case 5:
                return self::fromCompactSerializationRecipientToSerialization($parts);
            default:
                throw new \InvalidArgumentException('Unsupported input');
        }
    }

    /**
     * @param array $parts
     *
     * @return array
     */
    private static function fromCompactSerializationRecipientToSerialization(array $parts): array
    {
        $recipient = [];
        if (!empty($parts[1])) {
            $recipient['encrypted_key'] = $parts[1];
        }

        $recipients = [
            'recipients' => [$recipient],
        ];
        foreach ([0 => 'protected', 2 => 'iv', 3 => 'ciphertext', 4 => 'tag'] as $part => $key) {
            if (!empty($parts[$part])) {
                $recipients[$key] = $parts[$part];
            }
        }

        return $recipients;
    }

    /**
     * @param array $data
     *
     * @return JWE
     */
    private static function loadSerializedJsonJWE(array $data): JWE
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
     * @param JWE   $jwe
     * @param array $data
     */
    private static function populateIV(JWE &$jwe, array $data)
    {
        if (array_key_exists('iv', $data)) {
            $jwe = $jwe->withIV(Base64Url::decode($data['iv']));
        }
    }

    /**
     * @param JWE   $jwe
     * @param array $data
     */
    private static function populateAAD(JWE &$jwe, array $data)
    {
        if (array_key_exists('aad', $data)) {
            $jwe = $jwe->withAAD(Base64Url::decode($data['aad']));
        }
    }

    /**
     * @param JWE   $jwe
     * @param array $data
     */
    private static function populateTag(JWE &$jwe, array $data)
    {
        if (array_key_exists('tag', $data)) {
            $jwe = $jwe->withTag(Base64Url::decode($data['tag']));
        }
    }

    /**
     * @param JWE   $jwe
     * @param array $data
     */
    private static function populateSharedProtectedHeaders(JWE &$jwe, array $data)
    {
        if (array_key_exists('protected', $data)) {
            $jwe = $jwe->withEncodedSharedProtectedHeaders($data['protected']);
            $jwe = $jwe->withSharedProtectedHeaders(json_decode(Base64Url::decode($data['protected']), true));
        }
    }

    /**
     * @param JWE   $jwe
     * @param array $data
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
