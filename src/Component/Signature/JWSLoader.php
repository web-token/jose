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
        $json = JWSConverter::convert($input);

        $jws = JWS::create();

        foreach ($json['signatures'] as $signature) {
            $bin_signature = Base64Url::decode($signature['signature']);
            $protected_headers = self::getProtectedHeaders($signature);
            $headers = self::getHeaders($signature);

            $jws = $jws->addSignature($bin_signature, $protected_headers, $headers);
        }

        self::populatePayload($jws, $json);

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