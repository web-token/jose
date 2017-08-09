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

final class JtiChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(array $claims): array
    {
        if (!array_key_exists('jti', $claims)) {
            return [];
        }

        $jti = $claims['jti'];
        Assertion::string($jti, 'Invalid claim "jti". The value must be a string.');
        Assertion::true($this->isJtiValid($jti), sprintf('Invalid token ID "%s".', $jti));

        return ['jti'];
    }

    /**
     * @param string $jti
     *
     * @return bool
     */
    private function isJtiValid(string $jti): bool
    {
        return in_array($jti, ['JTI1', 'JTI2']);
    }
}
