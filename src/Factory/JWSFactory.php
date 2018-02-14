<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Assert\Assertion;
use Jose\Object\JWKInterface;
use Jose\Object\JWS;
use Jose\Signer;

final class JWSFactory implements JWSFactoryInterface
{
    /**
     * {@inheritdoc}
     */
    public static function createJWS($payload, $is_payload_detached = false)
    {
        $jws = new JWS();
        $jws = $jws->withPayload($payload);
        if (true === $is_payload_detached) {
            $jws = $jws->withDetachedPayload();
        } else {
            $jws = $jws->withAttachedPayload();
        }

        return $jws;
    }

    /**
     * {@inheritdoc}
     */
    public static function createJWSToCompactJSON($payload, JWKInterface $signature_key, array $protected_headers)
    {
        $jws = self::createJWSAndSign($payload, $signature_key, $protected_headers, []);

        return $jws->toCompactJSON(0);
    }

    /**
     * {@inheritdoc}
     */
    public static function createJWSWithDetachedPayloadToCompactJSON($payload, JWKInterface $signature_key, array $protected_headers)
    {
        $jws = self::createJWSWithDetachedPayloadAndSign($payload, $signature_key, $protected_headers, []);

        return $jws->toCompactJSON(0);
    }

    /**
     * {@inheritdoc}
     */
    public static function createJWSToFlattenedJSON($payload, JWKInterface $signature_key, array $protected_headers = [], $headers = [])
    {
        $jws = self::createJWSAndSign($payload, $signature_key, $protected_headers, $headers);

        return $jws->toFlattenedJSON(0);
    }

    /**
     * {@inheritdoc}
     */
    public static function createJWSWithDetachedPayloadToFlattenedJSON($payload, JWKInterface $signature_key, array $protected_headers = [], $headers = [])
    {
        $jws = self::createJWSWithDetachedPayloadAndSign($payload, $signature_key, $protected_headers, $headers);

        return $jws->toFlattenedJSON(0);
    }

    /**
     * @param mixed                     $payload
     * @param \Jose\Object\JWKInterface $signature_key
     * @param array                     $protected_headers
     *
     * @return \Jose\Object\JWSInterface
     */
    private static function createJWSAndSign($payload, JWKInterface $signature_key, array $protected_headers = [], $headers = [])
    {
        $jws = self::createJWS($payload);

        $jws = $jws->addSignatureInformation($signature_key, $protected_headers, $headers);

        $complete_headers = array_merge($protected_headers, $headers);
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header');
        $signer = Signer::createSigner([$complete_headers['alg']]);
        $signer->sign($jws);

        return $jws;
    }

    /**
     * @param mixed                     $payload
     * @param \Jose\Object\JWKInterface $signature_key
     * @param array                     $protected_headers
     *
     * @return \Jose\Object\JWSInterface
     */
    private static function createJWSWithDetachedPayloadAndSign($payload, JWKInterface $signature_key, array $protected_headers = [], $headers = [])
    {
        $jws = self::createJWS($payload, true);

        $jws = $jws->addSignatureInformation($signature_key, $protected_headers, $headers);

        $complete_headers = array_merge($protected_headers, $headers);
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header');
        $signer = Signer::createSigner([$complete_headers['alg']]);
        $signer->sign($jws);

        return $jws;
    }
}
