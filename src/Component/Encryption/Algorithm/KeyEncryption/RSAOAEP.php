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

/**
 * Class RSAOAEP.
 */
final class RSAOAEP extends RSA
{
    /**
     * {@inheritdoc}
     */
    protected function getEncryptionMode(): int
    {
        return self::ENCRYPTION_OAEP;
    }

    /**
     * {@inheritdoc}
     */
    protected function getHashAlgorithm(): string
    {
        return 'sha1';
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'RSA-OAEP';
    }
}
