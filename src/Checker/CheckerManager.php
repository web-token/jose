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
use Jose\Object;

/**
 * Class CheckerManager.
 */
class CheckerManager implements CheckerManagerInterface
{
    /**
     * @var \Jose\Checker\ClaimCheckerInterface[]
     */
    private $claim_checkers = [];

    /**
     * @var \Jose\Checker\HeaderCheckerInterface[]
     */
    private $header_checkers = [];

    /**
     * @param \Jose\Object\JWTInterface $jwt
     *
     * @return string[]
     */
    private function checkJWT(Object\JWTInterface $jwt)
    {
        $checked_claims = [];

        foreach ($this->claim_checkers as $claim_checker) {
            $checked_claims = array_merge(
                $checked_claims,
                $claim_checker->checkClaim($jwt)
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
     * {@inheritdoc}
     */
    public function checkJWS(Object\JWSInterface $jws, $signature)
    {
        Assertion::integer($signature);
        Assertion::lessThan($signature, $jws->countSignatures());

        $checked_claims = $this->checkJWT($jws);
        $protected_headers = $jws->getSignature($signature)->getProtectedHeaders();
        $headers = $jws->getSignature($signature)->getHeaders();

        $this->checkHeaders($protected_headers, $headers, $checked_claims);
    }

    /**
     * @param \Jose\Checker\ClaimCheckerInterface $claim_checker
     */
    public function addClaimChecker(ClaimCheckerInterface $claim_checker)
    {
        $this->claim_checkers[] = $claim_checker;
    }

    /**
     * @param \Jose\Checker\HeaderCheckerInterface $header_checker
     */
    public function addHeaderChecker(HeaderCheckerInterface $header_checker)
    {
        $this->header_checkers[] = $header_checker;
    }
}
