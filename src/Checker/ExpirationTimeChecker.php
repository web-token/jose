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

class ExpirationTimeChecker implements ClaimCheckerInterface
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
        if (!$jwt->hasClaim('exp')) {
            return [];
        }

        $exp = (int) $jwt->getClaim('exp') + $this->tolerance;
        Assertion::greaterOrEqualThan($exp, time(), 'The JWT has expired.');

        return ['exp'];
    }
}
