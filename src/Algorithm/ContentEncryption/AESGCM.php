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

        return GCM::decrypt($cek, $iv, $data, $calculated_aad, $tag);
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
