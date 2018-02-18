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
use Jose\Algorithm\JWAInterface;
use Jose\Algorithm\JWAManager;

final class AlgorithmManagerFactory
{
    /**
     * @param string[]|\Jose\Algorithm\JWAInterface[] $algorithms
     *
     * @return \Jose\Algorithm\JWAManagerInterface
     */
    public static function createAlgorithmManager(array $algorithms)
    {
        $jwa_manager = new JWAManager();

        foreach ($algorithms as $algorithm) {
            if ($algorithm instanceof JWAInterface) {
                $jwa_manager->addAlgorithm($algorithm);
            } else {
                Assertion::string($algorithm, 'Bad argument: must be a list with either algorithm names (string) or instances of JWAInterface.');
                $class = self::getAlgorithmClass($algorithm);
                $jwa_manager->addAlgorithm(new $class());
            }
        }

        return $jwa_manager;
    }

    /**
     * @param string $algorithm
     *
     * @return bool
     */
    private static function isAlgorithmSupported($algorithm)
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
    private static function getAlgorithmClass($algorithm)
    {
        Assertion::true(self::isAlgorithmSupported($algorithm), sprintf('Algorithm "%s" is not supported.', $algorithm));

        return self::getSupportedAlgorithms()[$algorithm];
    }

    /**
     * @return array
     */
    private static function getSupportedAlgorithms()
    {
        return [
            'HS256' => '\Jose\Algorithm\Signature\HS256',
            'HS384' => '\Jose\Algorithm\Signature\HS384',
            'HS512' => '\Jose\Algorithm\Signature\HS512',
            'ES256' => '\Jose\Algorithm\Signature\ES256',
            'ES384' => '\Jose\Algorithm\Signature\ES384',
            'ES512' => '\Jose\Algorithm\Signature\ES512',
            'none' => '\Jose\Algorithm\Signature\None',
            'RS256' => '\Jose\Algorithm\Signature\RS256',
            'RS384' => '\Jose\Algorithm\Signature\RS384',
            'RS512' => '\Jose\Algorithm\Signature\RS512',
            'PS256' => '\Jose\Algorithm\Signature\PS256',
            'PS384' => '\Jose\Algorithm\Signature\PS384',
            'PS512' => '\Jose\Algorithm\Signature\PS512',
            'EdDSA' => '\Jose\Algorithm\Signature\EdDSA',
            'A128GCM' => '\Jose\Algorithm\ContentEncryption\A128GCM',
            'A192GCM' => '\Jose\Algorithm\ContentEncryption\A192GCM',
            'A256GCM' => '\Jose\Algorithm\ContentEncryption\A256GCM',
            'A128CBC-HS256' => '\Jose\Algorithm\ContentEncryption\A128CBCHS256',
            'A192CBC-HS384' => '\Jose\Algorithm\ContentEncryption\A192CBCHS384',
            'A256CBC-HS512' => '\Jose\Algorithm\ContentEncryption\A256CBCHS512',
            'A128KW' => '\Jose\Algorithm\KeyEncryption\A128KW',
            'A192KW' => '\Jose\Algorithm\KeyEncryption\A192KW',
            'A256KW' => '\Jose\Algorithm\KeyEncryption\A256KW',
            'A128GCMKW' => '\Jose\Algorithm\KeyEncryption\A128GCMKW',
            'A192GCMKW' => '\Jose\Algorithm\KeyEncryption\A192GCMKW',
            'A256GCMKW' => '\Jose\Algorithm\KeyEncryption\A256GCMKW',
            'dir' => '\Jose\Algorithm\KeyEncryption\Dir',
            'ECDH-ES' => '\Jose\Algorithm\KeyEncryption\ECDHES',
            'ECDH-ES+A128KW' => '\Jose\Algorithm\KeyEncryption\ECDHESA128KW',
            'ECDH-ES+A192KW' => '\Jose\Algorithm\KeyEncryption\ECDHESA192KW',
            'ECDH-ES+A256KW' => '\Jose\Algorithm\KeyEncryption\ECDHESA256KW',
            'PBES2-HS256+A128KW' => '\Jose\Algorithm\KeyEncryption\PBES2HS256A128KW',
            'PBES2-HS384+A192KW' => '\Jose\Algorithm\KeyEncryption\PBES2HS384A192KW',
            'PBES2-HS512+A256KW' => '\Jose\Algorithm\KeyEncryption\PBES2HS512A256KW',
            'RSA1_5' => '\Jose\Algorithm\KeyEncryption\RSA15',
            'RSA-OAEP' => '\Jose\Algorithm\KeyEncryption\RSAOAEP',
            'RSA-OAEP-256' => '\Jose\Algorithm\KeyEncryption\RSAOAEP256',
        ];
    }
}
