<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Component\Core\JWKInterface;

interface DirectEncryptionInterface extends KeyEncryptionAlgorithmInterface
{
    /**
     * @param \Jose\Component\Core\JWKInterface $key The key used to get the CEK
     *
     * @throws \Exception If key does not support the algorithm or if the key usage does not authorize the operation
     *
     * @return string The CEK
     */
    public function getCEK(JWKInterface $key): string;
}
