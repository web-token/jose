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

abstract class JtiChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWTInterface $jwt)
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
     *
     * @return bool
     */
    abstract protected function isJtiValid($jti);
}
