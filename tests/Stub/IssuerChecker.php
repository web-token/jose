<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\Stub;

use Assert\Assertion;
use Jose\Checker\ClaimCheckerInterface;
use Jose\Object\JWTInterface;

final class IssuerChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWTInterface $jwt): array
    {
        if (!$jwt->hasClaim('iss')) {
            return [];
        }

        $issuer = $jwt->getClaim('iss');
        Assertion::true($this->isIssuerAllowed($issuer), sprintf('The issuer "%s" is not allowed.', $issuer));

        return ['iss'];
    }

    /**
     * @param string $issuer
     * @return bool
     */
    protected function isIssuerAllowed(string $issuer): bool
    {
        return in_array($issuer, ['ISS1', 'ISS2']);
    }
}
