<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature\Algorithm;

use Assert\Assertion;
use Jose\Component\Signature\SignatureAlgorithmInterface;
use Jose\Component\Core\JWKInterface;

/**
 * This class is an abstract class that implements the none algorithm (plaintext).
 */
final class None implements SignatureAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function sign(JWKInterface $key, string $input): string
    {
        $this->checkKey($key);

        return '';
    }

    /**
     * {@inheritdoc}
     */
    public function verify(JWKInterface $key, string $input, string $signature): bool
    {
        return $signature === '';
    }

    /**
     * @param JWKInterface $key
     */
    private function checkKey(JWKInterface $key)
    {
        Assertion::eq($key->get('kty'), 'none', 'Wrong key type.');
    }

    /**
     * @return string
     */
    public function name(): string
    {
        return 'none';
    }
}
