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
 * Class RSA15.
 */
final class RSA15 extends RSA
{
    /**
     * {@inheritdoc}
     */
    protected function getEncryptionMode(): int
    {
        return self::ENCRYPTION_PKCS1;
    }

    /**
     * {@inheritdoc}
     *
     * @codeCoverageIgnore
     */
    protected function getHashAlgorithm(): string
    {
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'RSA1_5';
    }
}
