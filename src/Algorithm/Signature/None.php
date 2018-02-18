<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\Signature;

use Assert\Assertion;
use Jose\Algorithm\SignatureAlgorithmInterface;
use Jose\Object\JWKInterface;

/**
 * This class is an abstract class that implements the none algorithm (plaintext).
 */
final class None implements SignatureAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function sign(JWKInterface $key, $data)
    {
        $this->checkKey($key);

        return '';
    }

    /**
     * {@inheritdoc}
     */
    public function verify(JWKInterface $key, $data, $signature)
    {
        return $signature === $this->sign($key, $data);
    }

    /**
     * @param JWKInterface $key
     */
    protected function checkKey(JWKInterface $key)
    {
        Assertion::eq($key->get('kty'), 'none', 'Wrong key type.');
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'none';
    }
}
