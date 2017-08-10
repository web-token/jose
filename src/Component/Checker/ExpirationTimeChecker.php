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

final class ExpirationTimeChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(array $claims): array
    {
        if (!array_key_exists('exp', $claims)) {
            return [];
        }

        $exp = $claims['exp'];
        if (!is_int($exp)) {
            throw new \InvalidArgumentException('The claim "exp" must be an integer.');
        }
        if (time() > $exp) {
            throw new \InvalidArgumentException('The JWT has expired.');
        }

        return ['exp'];
    }
}
