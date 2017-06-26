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

final class KeyChecker
{
    /**
     * @param JWK    $key
     * @param string $usage
     *
     * @throws \InvalidArgumentException
     *
     * @return bool
     */
    public static function checkKeyUsage(JWK $key, string $usage): bool
    {
        if ($key->has('use')) {
            return self::checkUsage($key, $usage);
        }
        if ($key->has('key_ops')) {
            return self::checkOperation($key, $usage);
        }

        return true;
    }

    /**
     * @param JWK    $key
     * @param string $usage
     *
     * @return bool
     */
    private static function checkOperation(JWK $key, string $usage): bool
    {
        $ops = $key->get('key_ops');
        if (!is_array($ops)) {
            $ops = [$ops];
        }
        switch ($usage) {
            case 'verification':
                Assertion::inArray('verify', $ops, 'Key cannot be used to verify a signature');

                return true;
            case 'signature':
                Assertion::inArray('sign', $ops, 'Key cannot be used to sign');

                return true;
            case 'encryption':
                Assertion::true(in_array('encrypt', $ops) || in_array('wrapKey', $ops), 'Key cannot be used to encrypt');

                return true;
            case 'decryption':
                Assertion::true(in_array('decrypt', $ops) || in_array('unwrapKey', $ops), 'Key cannot be used to decrypt');

                return true;
            default:
                throw new \InvalidArgumentException('Unsupported key usage.');
        }
    }

    /**
     * @param JWK    $key
     * @param string $usage
     *
     * @return bool
     */
    private static function checkUsage(JWK $key, string $usage): bool
    {
        $use = $key->get('use');
        switch ($usage) {
            case 'verification':
            case 'signature':
                Assertion::eq('sig', $use, 'Key cannot be used to sign or verify a signature');

                return true;
            case 'encryption':
            case 'decryption':
                Assertion::eq('enc', $use, 'Key cannot be used to encrypt or decrypt');

                return true;
            default:
                throw new \InvalidArgumentException('Unsupported key usage.');
        }
    }

    /**
     * @param JWK    $key
     * @param string $algorithm
     */
    public static function checkKeyAlgorithm(JWK $key, string $algorithm)
    {
        if (!$key->has('alg')) {
            return;
        }

        Assertion::eq($key->get('alg'), $algorithm, sprintf('Key is only allowed for algorithm "%s".', $key->get('alg')));
    }
}
