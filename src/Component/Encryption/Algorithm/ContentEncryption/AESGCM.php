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

namespace Jose\Component\Encryption\Algorithm\ContentEncryption;

use Assert\Assertion;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithmInterface;

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

        $keyLength = mb_strlen($cek, '8bit') * 8;
        $this->checkKeyLength($keyLength);
        $mode = sprintf('aes-%d-gcm', $keyLength);
        $C = openssl_encrypt($data, $mode, $cek, OPENSSL_RAW_DATA, $iv, $tag, $calculated_aad);
        Assertion::true(false !== $C, 'Unable to encrypt the data.');

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

        $keyLength = mb_strlen($cek, '8bit') * 8;
        $this->checkKeyLength($keyLength);

        $mode = 'aes-'.($keyLength).'-gcm';
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
     * @param int $keyLength
     */
    private function checkKeyLength(int $keyLength)
    {
        if (!in_array($keyLength, [128, 192, 256])) {
            throw new \InvalidArgumentException('Invalid key length. Allowed sizes are 128, 192 and 256 bits.');
        }
    }

    /**
     * @return int
     */
    abstract protected function getKeySize(): int;
}
