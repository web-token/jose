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

final class IssuerChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(array $claims): array
    {
        if (!array_key_exists('iss', $claims)) {
            return [];
        }

        $iss = $claims['iss'];
        Assertion::string($iss, 'Invalid claim "iss". The value must be a string.');
        Assertion::true($this->isIssuerAllowed($iss), sprintf('The issuer "%s" is not allowed.', $iss));

        return ['iss'];
    }

    /**
     * @param string $iss
     *
     * @return bool
     */
    private function isIssuerAllowed(string $iss): bool
    {
        return in_array($iss, ['ISS1', 'ISS2']);
    }
}
