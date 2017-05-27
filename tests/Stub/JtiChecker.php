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

class JtiChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWTInterface $jwt): array
    {
        if (!$jwt->hasClaim('jti')) {
            return [];
        }

        $jti = $jwt->getClaim('jti');
        Assertion::true($this->isJtiValid($jti), sprintf('Invalid token ID "%s".', $jti));

        return ['jti'];
    }

    /**
     * @param string $jti
     * @return bool
     */
    protected function isJtiValid(string $jti): bool
    {
        return in_array($jti, ['JTI1', 'JTI2']);
    }
}
