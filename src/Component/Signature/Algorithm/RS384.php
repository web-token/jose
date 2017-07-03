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

/**
 * Class RS384.
 */
final class RS384 extends RSA
{
    /**
     * @return string
     */
    protected function getAlgorithm(): string
    {
        return 'sha384';
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
        return 'RS384';
    }
}
