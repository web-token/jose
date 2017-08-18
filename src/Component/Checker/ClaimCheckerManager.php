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

namespace Jose\Component\Checker;

use Jose\Component\Core\JWTInterface;

/**
 * Class ClaimCheckerManager.
 */
final class ClaimCheckerManager
{
    /**
     * @var ClaimCheckerInterface[]
     */
    private $checkers = [];

    /**
     * @param ClaimCheckerInterface $checker
     */
    public function add(ClaimCheckerInterface $checker)
    {
        $this->checkers[$checker->supportedClaim()] = $checker;
    }

    /**
     * @param JWTInterface $jwt
     */
    public function check(JWTInterface $jwt)
    {
        $claims = json_decode($jwt->getPayload(), true);
        if (!is_array($claims)) {
            throw new \InvalidArgumentException('The payload is does not contain claims.');
        }

        foreach ($this->checkers as $claim => $checker) {
            if (array_key_exists($claim, $claims)) {
                $checker->checkClaim($claims[$claim]);
            }
        }
    }
}
