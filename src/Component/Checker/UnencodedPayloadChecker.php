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

namespace Jose\Component\Checker;

/**
 * Class UnencodedPayloadChecker.
 */
final class UnencodedPayloadChecker implements HeaderCheckerInterface
{
    private const HEADER_NAME = 'b64';

    /**
     * {@inheritdoc}
     */
    public function checkHeader($value)
    {
        // Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function supportedHeader(): string
    {
        return self::HEADER_NAME;
    }

    /**
     * {@inheritdoc}
     */
    public function protectedHeaderOnly(): bool
    {
        return true;
    }
}
