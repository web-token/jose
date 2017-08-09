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

use Jose\Component\Core\JWTInterface;

/**
 * Interface ClaimCheckerInterface.
 */
interface ClaimCheckerInterface
{
    /**
     * @param array $claims
     *
     * @throws \InvalidArgumentException
     *
     * @return string[]
     */
    public function checkClaim(array $claims): array;
}
