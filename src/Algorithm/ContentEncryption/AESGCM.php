<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\ContentEncryption;

use Assert\Assertion;
use Jose\Algorithm\ContentEncryptionAlgorithmInterface;

abstract class AESGCM implements ContentEncryptionAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function encryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, ?string &$tag): string
    {
        $calculated_aad = $encoded_protected_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
        }

        $key_length = mb_strlen($cek, '8bit') * 8;
        $mode = sprintf('aes-%d-gcm', $key_length);
        $C = openssl_encrypt($data, $mode, $cek, OPENSSL_RAW_DATA, $iv, $tag, $calculated_aad);
        Assertion::true(false !== $C, 'Unable to encrypt the data.');
        //list($cyphertext, $tag) = GCM::encrypt($cek, $iv, $data, $calculated_aad);

        return $C;
    }

    /**
     *  {@inheritdoc}
     */
    public function decryptContent(string $data, string $cek, string $iv, ?string $aad, string $encoded_protected_header, string $tag): string
    {
        $calculated_aad = $encoded_protected_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
        }

        // $K,   $IV, $C,    $A,              $T
        // $cek, $iv, $data, $calculated_aad, $tag
        $key_length = mb_strlen($cek, '8bit') * 8;

        $mode = 'aes-'.($key_length).'-gcm';
        $P = openssl_decrypt($data, $mode, $cek, OPENSSL_RAW_DATA, $iv, $tag, $calculated_aad);
        Assertion::true(false !== $P, 'Unable to decrypt or to verify the tag.');

        return $P;
    }

    /**
     * @return int
     */
    public function getIVSize(): int
    {
        return 96;
    }

    /**
     * @return int
     */
    public function getCEKSize(): int
    {
        return $this->getKeySize();
    }

    /**
     * @return int
     */
    abstract protected function getKeySize(): int;
}
