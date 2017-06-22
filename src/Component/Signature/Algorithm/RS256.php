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

/**
 * Class RS256.
 */
final class RS256 extends RSA
{
    /**
     * @return string
     */
    protected function getAlgorithm(): string
    {
        return 'sha256';
    }

    /**
     * @return int
     */
    protected function getSignatureMethod(): int
    {
        return self::SIGNATURE_PKCS1;
    }

    /**
     * @return string
     */
    public function name(): string
    {
        return 'RS256';
    }
}
