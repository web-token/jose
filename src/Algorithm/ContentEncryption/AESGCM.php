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

use AESGCM\AESGCM as GCM;
use Crypto\Cipher;
use Jose\Algorithm\ContentEncryptionAlgorithmInterface;

abstract class AESGCM implements ContentEncryptionAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function encryptContent($data, $cek, $iv, $aad, $encoded_protected_header, &$tag)
    {
        $calculated_aad = $encoded_protected_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
        }

        list($cyphertext, $tag) = GCM::encrypt($cek, $iv, $data, $calculated_aad);

        return $cyphertext;
    }

    /**
     *  {@inheritdoc}
     */
    public function decryptContent($data, $cek, $iv, $aad, $encoded_protected_header, $tag)
    {
        $calculated_aad = $encoded_protected_header;
        if (null !== $aad) {
            $calculated_aad .= '.'.$aad;
        }

        if (version_compare(PHP_VERSION, '7.1.0') >= 0) {
            return openssl_decrypt($data, $this->getMode($cek), $cek, OPENSSL_RAW_DATA, $iv, $tag, $calculated_aad);
        } elseif (class_exists('\Crypto\Cipher')) {
            $cipher = Cipher::aes(Cipher::MODE_GCM, $this->getKeySize());
            $cipher->setTag($tag);
            $cipher->setAAD($calculated_aad);

            $plaintext = $cipher->decrypt($data, $cek, $iv);

            return $plaintext;
        }

        return GCM::decrypt($cek, $iv, $data, $calculated_aad, $tag);
    }

    /**
     * @param string $k
     *
     * @return string
     */
    private function getMode($k)
    {
        return 'aes-'.(8 * mb_strlen($k, '8bit')).'-gcm';
    }

    /**
     * @return int
     */
    public function getIVSize()
    {
        return 96;
    }

    /**
     * @return int
     */
    public function getCEKSize()
    {
        return $this->getKeySize();
    }

    /**
     * @return int
     */
    abstract protected function getKeySize();
}
