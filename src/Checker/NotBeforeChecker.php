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

class NotBeforeChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWTInterface $jwt)
    {
        if (!$jwt->hasClaim('nbf')) {
            return [];
        }

        $nbf = (int) $jwt->getClaim('nbf');
        Assertion::lessOrEqualThan($nbf, time(), 'The JWT can not be used yet.');

        return ['nbf'];
    }
}
