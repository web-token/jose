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
 * This class handles signatures using HMAC.
 * It supports HS256;.
 */
/**
 * Class HS256.
 */
final class HS256 extends HMAC
{
    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha256';
    }

    /**
     * @return string
     */
    public function getAlgorithmName()
    {
        return 'HS256';
    }
}
