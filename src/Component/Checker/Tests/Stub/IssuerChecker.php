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
        if (!is_string($iss)) {
            throw new \InvalidArgumentException('The claim "iss" must be an string.');
        }
        if (!$this->isIssuerAllowed($iss)) {
            throw new \InvalidArgumentException(sprintf('The issuer "%s" is not allowed.', $iss));
        }

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
