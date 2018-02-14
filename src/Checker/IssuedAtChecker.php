<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Checker;

use Assert\Assertion;
use Jose\Object\JWTInterface;

class IssuedAtChecker implements ClaimCheckerInterface
{
    /**
     * @var int
     */
    private $tolerance;

    /**
     * @param int $tolerance
     */
    public function __construct($tolerance = 0)
    {
        Assertion::greaterOrEqualThan($tolerance, 0, 'Tolerance value must be >=0');
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
