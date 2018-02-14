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
use Jose\Encrypter;
use Jose\Object\JWE;
use Jose\Object\JWKInterface;

final class JWEFactory implements JWEFactoryInterface
{
    /**
     * {@inheritdoc}
     */
    public static function createJWE($payload, array $shared_protected_headers = [], array $shared_headers = [], $aad = null)
    {
        $jwe = new JWE();
        $jwe = $jwe->withSharedProtectedHeaders($shared_protected_headers);
        $jwe = $jwe->withSharedHeaders($shared_headers);
        $jwe = $jwe->withPayload($payload);

        if (null !== $aad) {
            $jwe = $jwe->withAAD($aad);
        }

        return $jwe;
    }

    /**
     * {@inheritdoc}
     */
    public static function createJWEToCompactJSON($payload, JWKInterface $recipient_key, array $shared_protected_headers)
    {
        $jwe = self::createJWEAndEncrypt($payload, $recipient_key, $shared_protected_headers, [], [], null);

        return $jwe->toCompactJSON(0);
    }

    /**
     * {@inheritdoc}
     */
    public static function createJWEToFlattenedJSON($payload, JWKInterface $recipient_key, array $shared_protected_headers = [], $shared_headers = [], $recipient_headers = [], $aad = null)
    {
        $jwe = self::createJWEAndEncrypt($payload, $recipient_key, $shared_protected_headers, $shared_headers, $recipient_headers, $aad);

        return $jwe->toFlattenedJSON(0);
    }

    /**
     * @param mixed                     $payload
     * @param \Jose\Object\JWKInterface $recipient_key
     * @param array                     $shared_protected_headers
     * @param array                     $shared_headers
     * @param array                     $recipient_headers
     * @param string|null               $aad
     *
     * @return \Jose\Object\JWEInterface
     */
    private static function createJWEAndEncrypt($payload, JWKInterface $recipient_key, array $shared_protected_headers = [], $shared_headers = [], $recipient_headers = [], $aad = null)
    {
        $complete_headers = array_merge($shared_protected_headers, $shared_headers, $recipient_headers);
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header');
        Assertion::keyExists($complete_headers, 'enc', 'No "enc" parameter set in the header');
        $encrypter = Encrypter::createEncrypter([$complete_headers['alg']], [$complete_headers['enc']], ['DEF', 'ZLIB', 'GZ']);

        $jwe = self::createJWE($payload, $shared_protected_headers, $shared_headers, $aad);

        $jwe = $jwe->addRecipientInformation($recipient_key, $recipient_headers);

        $encrypter->encrypt($jwe);

        return $jwe;
    }
}
