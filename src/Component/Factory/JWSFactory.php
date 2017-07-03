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

namespace Jose\Component\Factory;

use Assert\Assertion;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;

final class JWSFactory
{
    /**
     * @param mixed $payload
     * @param bool  $is_payload_detached
     *
     * @return JWS
     */
    public static function createJWS($payload, bool $is_payload_detached = false): JWS
    {
        $jws = new JWS();
        $jws = $jws->withPayload($payload);
        if (true === $is_payload_detached) {
            return $jws->withDetachedPayload();
        }

        return $jws->withAttachedPayload();
    }

    /**
     * @param mixed $payload
     * @param JWK   $signature_key
     * @param array $protected_headers
     *
     * @return string
     */
    public static function createJWSToCompactJSON($payload, JWK $signature_key, array $protected_headers): string
    {
        $jws = self::createJWSAndSign($payload, $signature_key, $protected_headers, []);

        return $jws->toCompactJSON(0);
    }

    /**
     * @param mixed $payload
     * @param JWK   $signature_key
     * @param array $protected_headers
     *
     * @return string
     */
    public static function createJWSWithDetachedPayloadToCompactJSON($payload, JWK $signature_key, array $protected_headers): string
    {
        $jws = self::createJWSWithDetachedPayloadAndSign($payload, $signature_key, $protected_headers, []);

        return $jws->toCompactJSON(0);
    }

    /**
     * @param mixed $payload
     * @param JWK   $signature_key
     * @param array $protected_headers
     * @param array $headers
     *
     * @return string
     */
    public static function createJWSToFlattenedJSON($payload, JWK $signature_key, array $protected_headers = [], $headers = []): string
    {
        $jws = self::createJWSAndSign($payload, $signature_key, $protected_headers, $headers);

        return $jws->toFlattenedJSON(0);
    }

    /**
     * @param mixed $payload
     * @param JWK   $signature_key
     * @param array $protected_headers
     * @param array $headers
     *
     * @return string
     */
    public static function createJWSWithDetachedPayloadToFlattenedJSON($payload, JWK $signature_key, array $protected_headers = [], array $headers = []): string
    {
        $jws = self::createJWSWithDetachedPayloadAndSign($payload, $signature_key, $protected_headers, $headers);

        return $jws->toFlattenedJSON(0);
    }

    /**
     * @param mixed $payload
     * @param JWK   $signature_key
     * @param array $protected_headers
     * @param array $headers
     *
     * @return JWS
     */
    private static function createJWSAndSign($payload, JWK $signature_key, array $protected_headers = [], array $headers = []): JWS
    {
        $complete_headers = array_merge($protected_headers, $headers);
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header');
        $signatureAlgorithmManager = JWAManagerFactory::createFromAlgorithmName([$complete_headers['alg']]);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload($payload)
            ->addSignature($signature_key, $protected_headers, $headers);

        return $jwsBuilder->build();
    }

    /**
     * @param mixed $payload
     * @param JWK   $signature_key
     * @param array $protected_headers
     * @param array $headers
     *
     * @return JWS
     */
    private static function createJWSWithDetachedPayloadAndSign($payload, JWK $signature_key, array $protected_headers = [], array $headers = []): JWS
    {
        $complete_headers = array_merge($protected_headers, $headers);
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header');
        $signatureAlgorithmManager = JWAManagerFactory::createFromAlgorithmName([$complete_headers['alg']]);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload($payload, true)
            ->addSignature($signature_key, $protected_headers, $headers);

        return $jwsBuilder->build();
    }
}
