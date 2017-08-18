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
        $ciphertext = Base64Url::decode($data['ciphertext']);
        $iv = array_key_exists('iv', $data) ? Base64Url::decode($data['iv']) : null;
        $aad = array_key_exists('aad', $data) ? Base64Url::decode($data['aad']) : null;
        $tag = array_key_exists('tag', $data) ? Base64Url::decode($data['tag']) : null;
        $encodedSharedProtectedHeader = array_key_exists('protected', $data) ? $data['protected'] : null;
        $sharedProtectedHeader = $encodedSharedProtectedHeader ? json_decode(Base64Url::decode($encodedSharedProtectedHeader), true) : [];
        $sharedHeader = array_key_exists('unprotected', $data) ? $data['unprotected'] : [];
        $recipients = [];
        foreach ($data['recipients'] as $recipient) {
            $encryptedKey = array_key_exists('encrypted_key', $recipient) ? Base64Url::decode($recipient['encrypted_key']) : null;
            $header = array_key_exists('header', $recipient) ? $recipient['header'] : [];
            $recipients[] = Recipient::create($header, $encryptedKey);
        }

        return JWE::create($ciphertext, $iv, $aad, $tag, $sharedHeader, $sharedProtectedHeader, $encodedSharedProtectedHeader, $recipients);
    }
}
