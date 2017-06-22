<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker;

use Assert\Assertion;
use Jose\Component\Signature\Object\JWS;

final class ExpirationTimeChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWS $jwt): array
    {
        if (!$jwt->hasClaim('exp')) {
            return [];
        }

        $exp = (int) $jwt->getClaim('exp');
        Assertion::greaterThan($exp, time(), 'The JWT has expired.');

        return ['exp'];
    }
}
