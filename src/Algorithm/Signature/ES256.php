<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\Signature;

final class ES256 extends ECDSA
{
    /**
     * @return string
     */
    protected function getHashAlgorithm()
    {
        return 'sha256';
    }

    /**
     * @return int
     */
    protected function getSignaturePartLength()
    {
        return 64;
    }

    /**
     * @return string
     */
    public function name(): string
    {
        return 'ES256';
    }
}
