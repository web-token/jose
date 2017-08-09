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

namespace Jose\Component\Signature\Algorithm;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\SignatureAlgorithmInterface;

/**
 * This class handles signatures using HMAC.
 * It supports algorithms HS256, HS384 and HS512;.
 */
abstract class HMAC implements SignatureAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function sign(JWK $key, string $input): string
    {
        $this->checkKey($key);

        return hash_hmac($this->getHashAlgorithm(), $input, Base64Url::decode($key->get('k')), true);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(JWK $key, string $input, string $signature): bool
    {
        return hash_equals($this->sign($key, $input), $signature);
    }

    /**
     * @param JWK $key
     */
    protected function checkKey(JWK $key)
    {
        Assertion::eq($key->get('kty'), 'oct', 'Wrong key type.');
        Assertion::true($key->has('k'), 'The key parameter "k" is missing.');
    }

    /**
     * @return string
     */
    abstract protected function getHashAlgorithm(): string;
}