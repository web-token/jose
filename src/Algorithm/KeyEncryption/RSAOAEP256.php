<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\KeyEncryption;

/**
 * Class RSAOAEP256.
 */
final class RSAOAEP256 extends RSA
{
    /**
     * {@inheritdoc}
     */
    public function getEncryptionMode(): int
    {
        return self::ENCRYPTION_OAEP;
    }

    /**
     * {@inheritdoc}
     */
    public function getHashAlgorithm(): string
    {
        return 'sha256';
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'RSA-OAEP-256';
    }
}
