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

use Jose\Object\JWSInterface;

/**
 * Interface CheckerManagerInterface.
 */
interface CheckerManagerInterface
{
    /**
     * @param \Jose\Object\JWSInterface $jws
     * @param int                       $signature
     */
    public function checkJWS(JWSInterface $jws, $signature);

    /**
     * @param \Jose\Checker\ClaimCheckerInterface $claim_checker
     */
    public function addClaimChecker(ClaimCheckerInterface $claim_checker);

    /**
     * @param \Jose\Checker\HeaderCheckerInterface $header_checker
     */
    public function addHeaderChecker(HeaderCheckerInterface $header_checker);
}
