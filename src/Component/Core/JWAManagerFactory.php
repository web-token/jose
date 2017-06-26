<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core;

use Assert\Assertion;

final class JWAManagerFactory
{
    /**
     * @param JWAInterface[] $algorithms
     *
     * @return JWAManager
     */
    public static function createFromAlgorithms(array $algorithms): JWAManager
    {
        $jwa_manager = new JWAManager();

        foreach ($algorithms as $algorithm) {
            if ($algorithm instanceof JWAInterface) {
                $jwa_manager->add($algorithm);
            } else {
                throw new \InvalidArgumentException('The list must only contains objects that implement the JWAInterface.');
            }
        }

        return $jwa_manager;
    }

    /**
     * @param string[] $algorithms
     *
     * @return JWAManager
     */
    public static function createFromAlgorithmName(array $algorithms): JWAManager
    {
        Assertion::allString($algorithms, 'The list must only contains algorithm names.');
        $jwa_manager = new JWAManager();

        foreach ($algorithms as $algorithm) {
            $class = self::getAlgorithmClass($algorithm);
            $jwa_manager->add(new $class());
        }

        return $jwa_manager;
    }

    /**
     * @param string $algorithm
     *
     * @return bool
     */
    private static function isAlgorithmSupported(string $algorithm): bool
    {
        return array_key_exists($algorithm, self::getSupportedAlgorithms());
    }

    /**
     * @param string $algorithm
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function getAlgorithmClass(string $algorithm): string
    {
        Assertion::true(self::isAlgorithmSupported($algorithm), sprintf('Algorithm "%s" is not supported.', $algorithm));

        return self::getSupportedAlgorithms()[$algorithm];
    }

    /**
     * @return array
     */
    private static function getSupportedAlgorithms(): array
    {
        return [
            'HS256' => '\Jose\Component\Signature\Algorithm\HS256',
            'HS384' => '\Jose\Component\Signature\Algorithm\HS384',
            'HS512' => '\Jose\Component\Signature\Algorithm\HS512',
            'ES256' => '\Jose\Component\Signature\Algorithm\ES256',
            'ES384' => '\Jose\Component\Signature\Algorithm\ES384',
            'ES512' => '\Jose\Component\Signature\Algorithm\ES512',
            'none' => '\Jose\Component\Signature\Algorithm\None',
            'RS256' => '\Jose\Component\Signature\Algorithm\RS256',
            'RS384' => '\Jose\Component\Signature\Algorithm\RS384',
            'RS512' => '\Jose\Component\Signature\Algorithm\RS512',
            'PS256' => '\Jose\Component\Signature\Algorithm\PS256',
            'PS384' => '\Jose\Component\Signature\Algorithm\PS384',
            'PS512' => '\Jose\Component\Signature\Algorithm\PS512',
            'EdDSA' => '\Jose\Component\Signature\Algorithm\EdDSA',
            'A128GCM' => '\Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM',
            'A192GCM' => '\Jose\Component\Encryption\Algorithm\ContentEncryption\A192GCM',
            'A256GCM' => '\Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM',
            'A128CBC-HS256' => '\Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256',
            'A192CBC-HS384' => '\Jose\Component\Encryption\Algorithm\ContentEncryption\A192CBCHS384',
            'A256CBC-HS512' => '\Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512',
            'A128KW' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW',
            'A192KW' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\A192KW',
            'A256KW' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW',
            'A128GCMKW' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\A128GCMKW',
            'A192GCMKW' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\A192GCMKW',
            'A256GCMKW' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW',
            'dir' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\Dir',
            'ECDH-ES' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES',
            'ECDH-ES+A128KW' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW',
            'ECDH-ES+A192KW' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA192KW',
            'ECDH-ES+A256KW' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW',
            'PBES2-HS256+A128KW' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS256A128KW',
            'PBES2-HS384+A192KW' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS384A192KW',
            'PBES2-HS512+A256KW' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW',
            'RSA1_5' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\RSA15',
            'RSA-OAEP' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP',
            'RSA-OAEP-256' => '\Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256',
        ];
    }
}
