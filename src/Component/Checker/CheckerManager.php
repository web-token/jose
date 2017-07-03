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

use Assert\Assertion;
use Jose\Component\Core\JWT;

/**
 * Class CheckerManager.
 */
final class CheckerManager
{
    /**
     * @var ClaimCheckerInterface[]
     */
    private $claimCheckers = [];

    /**
     * @var HeaderCheckerInterface[]
     */
    private $headerCheckers = [];

    /**
     * @param JWT $jwt
     * @param int $signature
     */
    public function checkJWS(JWT $jwt, int $signature)
    {
        Assertion::lessThan($signature, $jwt->countSignatures());

        $checked_claims = $this->checkClaims($jwt);
        $protectedHeaders = $jwt->getSignature($signature)->getProtectedHeaders();
        $headers = $jwt->getSignature($signature)->getHeaders();

        $this->checkHeaders($protectedHeaders, $headers, $checked_claims);
    }

    /**
     * @param JWT $jwt
     *
     * @return string[]
     */
    public function checkClaims(JWT $jwt): array
    {
        $checked_claims = [];

        foreach ($this->claimCheckers as $claimChecker) {
            $checked_claims = array_merge(
                $checked_claims,
                $claimChecker->checkClaim($jwt)
            );
        }

        return $checked_claims;
    }

    /**
     * @param array $protectedHeaders
     * @param array $headers
     * @param array $checked_claims
     */
    public function checkHeaders(array $protectedHeaders, array $headers, array $checked_claims)
    {
        foreach ($this->headerCheckers as $headerChecker) {
            $headerChecker->checkHeader($protectedHeaders, $headers, $checked_claims);
        }
    }

    /**
     * @param ClaimCheckerInterface $claimChecker
     */
    public function addClaimChecker(ClaimCheckerInterface $claimChecker)
    {
        $this->claimCheckers[] = $claimChecker;
    }

    /**
     * @param HeaderCheckerInterface $headerChecker
     */
    public function addHeaderChecker(HeaderCheckerInterface $headerChecker)
    {
        $this->headerCheckers[] = $headerChecker;
    }
}
