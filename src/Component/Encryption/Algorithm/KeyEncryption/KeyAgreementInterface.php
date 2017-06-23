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

interface KeyAgreementInterface extends KeyEncryptionAlgorithmInterface
{
    /**
     * @param int                       $encryption_key_length    Size of the key expected for the algorithm used for data encryption
     * @param string                    $algorithm                The algorithm
     * @param JWKInterface $recipient_key            The recipient key. If the key is public, then an ephemeral private key will be created, else will try to find the ephemeral key in the header
     * @param array                     $complete_header          The complete header of the JWT
     * @param array                     $additional_header_values Set additional header values if needed
     *
     * @return string
     */
    public function getAgreementKey(int $encryption_key_length, string $algorithm, JWKInterface $recipient_key, array $complete_header = [], array &$additional_header_values = []): string;
}
