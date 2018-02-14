<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\KeyEncryption;

use Jose\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Object\JWKInterface;

interface KeyAgreementInterface extends KeyEncryptionAlgorithmInterface
{
    /**
     * @param int                       $encryption_key_length    Size of the key expected for the algorithm used for data encryption
     * @param string                    $algorithm                The algorithm
     * @param \Jose\Object\JWKInterface $recipient_key            The recipient key. If the key is public, then an ephemeral private key will be created, else will try to find the ephemeral key in the header
     * @param array                     $complete_header          The complete header of the JWT
     * @param array                     $additional_header_values Set additional header values if needed
     *
     * @return mixed
     */
    public function getAgreementKey($encryption_key_length, $algorithm, JWKInterface $recipient_key, array $complete_header = [], array &$additional_header_values = []);
}
