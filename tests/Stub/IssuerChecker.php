<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\Stub;

use Assert\Assertion;
use Jose\Checker\ClaimCheckerInterface;
use Jose\Object\JWTInterface;

class IssuerChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWTInterface $jwt)
    {
        if (!$jwt->hasClaim('iss')) {
            return [];
        }

        $issuer = $jwt->getClaim('iss');
        Assertion::true($this->isIssuerAllowed($issuer), sprintf('The issuer "%s" is not allowed.', $issuer));

        return ['iss'];
    }

    /**
     * {@inheritdoc}
     */
    protected function isIssuerAllowed($issuer)
    {
        return in_array($issuer, ['ISS1', 'ISS2']);
    }
}
