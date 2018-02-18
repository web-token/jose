<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Behaviour;

use Assert\Assertion;
use Jose\Object\JWKInterface;

trait HasKeyChecker
{
    /**
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $usage
     *
     * @throws \InvalidArgumentException
     *
     * @return bool
     */
    protected function checkKeyUsage(JWKInterface $key, $usage)
    {
        if ($key->has('use')) {
            return $this->checkUsage($key, $usage);
        }
        if ($key->has('key_ops')) {
            return $this->checkOperation($key, $usage);
        }

        return true;
    }

    /**
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $usage
     *
     * @return bool
     */
    private function checkOperation(JWKInterface $key, $usage)
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
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $usage
     *
     * @return bool
     */
    private function checkUsage(JWKInterface $key, $usage)
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
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $algorithm
     */
    protected function checkKeyAlgorithm(JWKInterface $key, $algorithm)
    {
        if (!$key->has('alg')) {
            return;
        }

        Assertion::eq($key->get('alg'), $algorithm, sprintf('Key is only allowed for algorithm "%s".', $key->get('alg')));
    }
}
