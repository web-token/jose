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

namespace Jose\Component\Signature;

use Assert\Assertion;
use Base64Url\Base64Url;

/**
 * Class able to load JWS.
 */
final class JWSLoader
{
    /**
     * Load data and return a JWS object.
     * Compact, Flattened or complete serialization formats are supported.
     *
     * @param string $input A string that represents a JWS
     *
     * @return JWS
     */
    public static function load(string $input): JWS
    {
        $json = self::convert($input);

        return self::loadSerializedJson($json);
    }

    /**
     * @param string $input
     *
     * @return array
     */
    private static function convert(string $input): array
    {
        $data = json_decode($input, true);
        if (is_array($data)) {
            if (array_key_exists('signatures', $data)) {
                return $data;
            } elseif (array_key_exists('signature', $data)) {
                return self::fromFlattenedSerializationSignatureToSerialization($data);
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
    private static function fromFlattenedSerializationSignatureToSerialization(array $input): array
    {
        $signature = [
            'signature' => $input['signature'],
        ];

        foreach (['protected', 'header'] as $key) {
            if (array_key_exists($key, $input)) {
                $signature[$key] = $input[$key];
            }
        }

        $temp = [];
        if (!empty($input['payload'])) {
            $temp['payload'] = $input['payload'];
        }
        $temp['signatures'] = [$signature];

        return $temp;
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
            case 3:
                return self::fromCompactSerializationSignatureToSerialization($parts);
            default:
                throw new \InvalidArgumentException('Unsupported input');
        }
    }

    /**
     * @param array $parts
     *
     * @return array
     */
    private static function fromCompactSerializationSignatureToSerialization(array $parts): array
    {
        $temp = [];

        if (!empty($parts[1])) {
            $temp['payload'] = $parts[1];
        }
        $temp['signatures'] = [[
            'protected' => $parts[0],
            'signature' => $parts[2],
        ]];

        return $temp;
    }

    /**
     * @param array $data
     *
     * @return JWS
     */
    private static function loadSerializedJson(array $data): JWS
    {
        $jws = new JWS();

        foreach ($data['signatures'] as $signature) {
            $bin_signature = Base64Url::decode($signature['signature']);
            $protected_headers = self::getProtectedHeaders($signature);
            $headers = self::getHeaders($signature);

            $jws = $jws->addSignatureFromLoadedData($bin_signature, $protected_headers, $headers);
        }

        self::populatePayload($jws, $data);

        return $jws;
    }

    /**
     * @param array $data
     *
     * @return string|null
     */
    private static function getProtectedHeaders(array $data): ?string
    {
        if (array_key_exists('protected', $data)) {
            return $data['protected'];
        }

        return null;
    }

    /**
     * @param array $data
     *
     * @return array
     */
    private static function getHeaders(array $data): array
    {
        if (array_key_exists('header', $data)) {
            return $data['header'];
        }

        return [];
    }

    /**
     * @param JWS   $jws
     * @param array $data
     */
    private static function populatePayload(JWS &$jws, array $data)
    {
        if (array_key_exists('payload', $data)) {
            $isPayloadEncoded = null;
            foreach ($jws->getSignatures() as $signature) {
                if (null === $isPayloadEncoded) {
                    $isPayloadEncoded = self::isPayloadEncoded($signature);
                }
                Assertion::eq($isPayloadEncoded, self::isPayloadEncoded($signature), 'Foreign payload encoding detected. The JWS cannot be loaded.');
            }
            $payload = $data['payload'];
            $jws = $jws->withAttachedPayload();
            $jws = $jws->withEncodedPayload($payload);
            if (false !== $isPayloadEncoded) {
                $payload = Base64Url::decode($payload);
            }
            $json = json_decode($payload, true);
            if (null !== $json && !empty($payload)) {
                $payload = $json;
            }
            $jws = $jws->withPayload($payload);
        } else {
            $jws = $jws->withDetachedPayload();
        }
    }

    /**
     * @param Signature $signature
     *
     * @return bool
     */
    private static function isPayloadEncoded(Signature $signature): bool
    {
        return !$signature->hasProtectedHeader('b64') || true === $signature->getProtectedHeader('b64');
    }
}
