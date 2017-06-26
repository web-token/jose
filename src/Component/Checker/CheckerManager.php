<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker;

use Assert\Assertion;
use Jose\Component\Signature\JWS;

/**
 * Class CheckerManager.
 */
final class CheckerManager
{
    /**
     * @var ClaimCheckerInterface[]
     */
    private $claim_checkers = [];

    /**
     * @var HeaderCheckerInterface[]
     */
    private $header_checkers = [];

    /**
     * @param JWS $jws
     * @param int $signature
     */
    public function checkJWS(JWS $jws, int $signature)
    {
        Assertion::lessThan($signature, $jws->countSignatures());

        $checked_claims = $this->checkClaims($jws);
        $protected_headers = $jws->getSignature($signature)->getProtectedHeaders();
        $headers = $jws->getSignature($signature)->getHeaders();

        $this->checkHeaders($protected_headers, $headers, $checked_claims);
    }

    /**
     * @param JWS $jws
     *
     * @return string[]
     */
    private function checkClaims(JWS $jws): array
    {
        $checked_claims = [];

        foreach ($this->claim_checkers as $claim_checker) {
            $checked_claims = array_merge(
                $checked_claims,
                $claim_checker->checkClaim($jws)
            );
        }

        return $checked_claims;
    }

    /**
     * @param array $protected_headers
     * @param array $headers
     * @param array $checked_claims
     */
    private function checkHeaders(array $protected_headers, array $headers, array $checked_claims)
    {
        foreach ($this->header_checkers as $header_checker) {
            $header_checker->checkHeader($protected_headers, $headers, $checked_claims);
        }
    }

    /**
     * @param ClaimCheckerInterface $claim_checker
     */
    public function addClaimChecker(ClaimCheckerInterface $claim_checker)
    {
        $this->claim_checkers[] = $claim_checker;
    }

    /**
     * @param HeaderCheckerInterface $header_checker
     */
    public function addHeaderChecker(HeaderCheckerInterface $header_checker)
    {
        $this->header_checkers[] = $header_checker;
    }
}
