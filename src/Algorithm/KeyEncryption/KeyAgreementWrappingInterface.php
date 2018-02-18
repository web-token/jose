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

interface KeyAgreementWrappingInterface extends KeyEncryptionAlgorithmInterface
{
    /**
     * Wrap the agreement key.
     *
     * @param \Jose\Object\JWKInterface $receiver_key             The receiver's key
     * @param string                    $cek                      The CEK to wrap
     * @param int                       $encryption_key_length    Size of the key expected for the algorithm used for data encryption
     * @param array                     $complete_header          The complete header of the JWT
     * @param array                     $additional_header_values Set additional header values if needed
     *
     * @throws \Exception If key does not support the algorithm or if the key usage does not authorize the operation
     *
     * @return string The encrypted CEK
     */
    public function wrapAgreementKey(JWKInterface $receiver_key, $cek, $encryption_key_length, array $complete_header, array &$additional_header_values);

    /**
     * Unwrap the agreement key.
     *
     * @param \Jose\Object\JWKInterface $receiver_key          The receiver's key
     * @param string                    $encrypted_cek         The encrypted CEK
     * @param int                       $encryption_key_length Size of the key expected for the algorithm used for data encryption
     * @param array                     $complete_header       The complete header of the JWT
     *
     * @throws \Exception If key does not support the algorithm or if the key usage does not authorize the operation
     *
     * @return string The decrypted CEK
     */
    public function unwrapAgreementKey(JWKInterface $receiver_key, $encrypted_cek, $encryption_key_length, array $complete_header);
}
