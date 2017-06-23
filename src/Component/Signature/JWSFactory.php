<?php

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
use Jose\Component\Core\JWKInterface;
use Jose\Component\Signature\Object\JWS;
use Jose\Factory\AlgorithmManagerFactory;

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
     * @param mixed        $payload
     * @param JWKInterface $signature_key
     * @param array        $protected_headers
     *
     * @return string
     */
    public static function createJWSToCompactJSON($payload, JWKInterface $signature_key, array $protected_headers): string
    {
        $jws = self::createJWSAndSign($payload, $signature_key, $protected_headers, []);

        return $jws->toCompactJSON(0);
    }

    /**
     * @param mixed        $payload
     * @param JWKInterface $signature_key
     * @param array        $protected_headers
     *
     * @return string
     */
    public static function createJWSWithDetachedPayloadToCompactJSON($payload, JWKInterface $signature_key, array $protected_headers): string
    {
        $jws = self::createJWSWithDetachedPayloadAndSign($payload, $signature_key, $protected_headers, []);

        return $jws->toCompactJSON(0);
    }

    /**
     * @param mixed        $payload
     * @param JWKInterface $signature_key
     * @param array        $protected_headers
     * @param array        $headers
     *
     * @return string
     */
    public static function createJWSToFlattenedJSON($payload, JWKInterface $signature_key, array $protected_headers = [], $headers = []): string
    {
        $jws = self::createJWSAndSign($payload, $signature_key, $protected_headers, $headers);

        return $jws->toFlattenedJSON(0);
    }

    /**
     * @param mixed        $payload
     * @param JWKInterface $signature_key
     * @param array        $protected_headers
     * @param array        $headers
     *
     * @return string
     */
    public static function createJWSWithDetachedPayloadToFlattenedJSON($payload, JWKInterface $signature_key, array $protected_headers = [], array $headers = []): string
    {
        $jws = self::createJWSWithDetachedPayloadAndSign($payload, $signature_key, $protected_headers, $headers);

        return $jws->toFlattenedJSON(0);
    }

    /**
     * @param mixed        $payload
     * @param JWKInterface $signature_key
     * @param array        $protected_headers
     *
     * @return JWS
     */
    private static function createJWSAndSign($payload, JWKInterface $signature_key, array $protected_headers = [], array $headers = []): JWS
    {
        $jws = self::createJWS($payload);

        $jws = $jws->addSignatureInformation($signature_key, $protected_headers, $headers);

        $complete_headers = array_merge($protected_headers, $headers);
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header');
        $signatureAlgorithmManager = AlgorithmManagerFactory::createFromAlgorithmName([$complete_headers['alg']]);
        $signer = new Signer($signatureAlgorithmManager);
        $signer->sign($jws);

        return $jws;
    }

    /**
     * @param mixed        $payload
     * @param JWKInterface $signature_key
     * @param array        $protected_headers
     * @param array        $headers
     *
     * @return JWS
     */
    private static function createJWSWithDetachedPayloadAndSign($payload, JWKInterface $signature_key, array $protected_headers = [], array $headers = []): JWS
    {
        $jws = self::createJWS($payload, true);

        $jws = $jws->addSignatureInformation($signature_key, $protected_headers, $headers);

        $complete_headers = array_merge($protected_headers, $headers);
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header');
        $signatureAlgorithmManager = AlgorithmManagerFactory::createFromAlgorithmName([$complete_headers['alg']]);
        $signer = new Signer($signatureAlgorithmManager);
        $signer->sign($jws);

        return $jws;
    }
}
