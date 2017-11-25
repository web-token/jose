<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Checker;

use Assert\Assertion;
use Jose\Object\JWTInterface;

class IssuedAtChecker implements ClaimCheckerInterface
{
    private $tolerance;

    public function __construct($tolerance = 0)
    {
        $this->tolerance = (int) $tolerance;
    }

    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWTInterface $jwt)
    {
        if (!$jwt->hasClaim('iat')) {
            return [];
        }

        $iat = (int) $jwt->getClaim('iat') - $this->tolerance;
        Assertion::lessOrEqualThan($iat, time(), 'The JWT is issued in the future.');

        return ['iat'];
    }
}
