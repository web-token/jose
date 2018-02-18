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

/**
 * Class PS384.
 */
final class PS384 extends RSA
{
    /**
     * @return string
     */
    protected function getAlgorithm()
    {
        return 'sha384';
    }

    /**
     * @return int
     */
    protected function getSignatureMethod()
    {
        return self::SIGNATURE_PSS;
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'PS384';
    }
}
