<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Util;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Object\JWS;
use Jose\Object\JWSInterface;
use Jose\Object\SignatureInterface;

final class JWSLoader
{
    /**
     * @param array $data
     *
     * @return \Jose\Object\JWSInterface
     */
    public static function loadSerializedJsonJWS(array $data)
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
    private static function getProtectedHeaders(array $data)
    {
        if (array_key_exists('protected', $data)) {
            return $data['protected'];
        }
    }

    /**
     * @param array $data
     *
     * @return array
     */
    private static function getHeaders(array $data)
    {
        if (array_key_exists('header', $data)) {
            return $data['header'];
        }

        return [];
    }

    /**
     * @param \Jose\Object\JWSInterface $jws
     * @param array                     $data
     */
    private static function populatePayload(JWSInterface &$jws, array $data)
    {
        $is_encoded = null;
        foreach ($jws->getSignatures() as $signature) {
            if (null === $is_encoded) {
                $is_encoded = self::isPayloadEncoded($signature);
            }
            Assertion::eq($is_encoded, self::isPayloadEncoded($signature), 'Foreign payload encoding detected. The JWS cannot be loaded.');
        }
        if (array_key_exists('payload', $data)) {
            $payload = $data['payload'];
            $jws = $jws->withAttachedPayload();
            $jws = $jws->withEncodedPayload($payload);
            if (false !== $is_encoded) {
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
     * @param \Jose\Object\SignatureInterface $signature
     *
     * @return bool
     */
    private static function isPayloadEncoded(SignatureInterface $signature)
    {
        return !$signature->hasProtectedHeader('b64') || true === $signature->getProtectedHeader('b64');
    }
}
