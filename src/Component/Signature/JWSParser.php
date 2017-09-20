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

use Base64Url\Base64Url;

/**
 * Class able to parse JWS.
 */
final class JWSParser
{
    /**
     * Load data and return a JWS object.
     * Compact, Flattened or complete serialization formats are supported.
     *
     * @param string $input A string that represents a JWS
     *
     * @return JWS
     */
    public static function parse(string $input): JWS
    {
        $json = JWSConverter::convert($input);
        $isPayloadEncoded = null;

        if (array_key_exists('payload', $json)) {
            $rawPayload = $json['payload'];
        } else {
            $rawPayload = null;
        }
        $signatures = [];
        foreach ($json['signatures'] as $signature) {
            $encodedProtectedHeaders = self::getProtectedHeaders($signature);
            $protectedHeaders = null !== $encodedProtectedHeaders ? json_decode(Base64Url::decode($encodedProtectedHeaders), true) : [];
            $signatures[] = [
                'signature' => Base64Url::decode($signature['signature']),
                'protected' => $protectedHeaders,
                'encoded_protected' => $encodedProtectedHeaders,
                'header' => self::getHeaders($signature),
            ];
            if (null === $isPayloadEncoded) {
                $isPayloadEncoded = self::isPayloadEncoded($protectedHeaders);
            }
            if (self::isPayloadEncoded($protectedHeaders) !== $isPayloadEncoded) {
                throw new \InvalidArgumentException('Foreign payload encoding detected.');
            }
        }

        if (null === $rawPayload) {
            $payload = null;
        } else {
            $payload = false === $isPayloadEncoded ? $rawPayload : Base64Url::decode($rawPayload);
        }
        $jws = JWS::create($payload, $rawPayload);
        foreach ($signatures as $signature) {
            $jws = $jws->addSignature(
                $signature['signature'],
                $signature['protected'],
                $signature['encoded_protected'],
                $signature['header']
            );
        }

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
     * @param array $protectedHeaders
     *
     * @return bool
     */
    private static function isPayloadEncoded(array $protectedHeaders): bool
    {
        return !array_key_exists('b64', $protectedHeaders) || true === $protectedHeaders['b64'];
    }
}
