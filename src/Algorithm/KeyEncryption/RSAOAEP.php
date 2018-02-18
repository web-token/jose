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

/**
 * Class RSAOAEP.
 */
final class RSAOAEP extends RSA
{
    /**
     * {@inheritdoc}
     */
    protected function getEncryptionMode()
    {
        return self::ENCRYPTION_OAEP;
    }

    /**
     * {@inheritdoc}
     */
    protected function getHashAlgorithm()
    {
        return 'sha1';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithmName()
    {
        return 'RSA-OAEP';
    }
}
