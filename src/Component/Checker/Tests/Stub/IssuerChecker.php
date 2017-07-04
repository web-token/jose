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

namespace Jose\Component\Checker\Tests\Stub;

use Assert\Assertion;
use Jose\Component\Checker\ClaimCheckerInterface;
use Jose\Component\Core\JWT;

final class IssuerChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWT $jwt): array
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
     *
     * @return bool
     */
    private function isIssuerAllowed(string $issuer): bool
    {
        return in_array($issuer, ['ISS1', 'ISS2']);
    }
}
