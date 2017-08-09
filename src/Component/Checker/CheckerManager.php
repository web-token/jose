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
use Jose\Component\Core\JWTInterface;
use Jose\Component\Encryption\JWE;
use Jose\Component\Signature\JWS;

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
     * @param JWS $jws
     * @param int $signature
     */
    public function checkJWS(JWS $jws, int $signature)
    {
        $checked_claims = $this->checkClaims($jws);
        Assertion::lessThan($signature, $jws->countSignatures());
        $protectedHeaders = $jws->getSignature($signature)->getProtectedHeaders();
        $headers = $jws->getSignature($signature)->getHeaders();
        $this->checkHeaders($protectedHeaders, $headers, $checked_claims);
    }

    /**
     * @param JWE $jwe
     * @param int $recipient
     */
    public function checkJWE(JWE $jwe, int $recipient)
    {
        $checked_claims = $this->checkClaims($jwe);
        Assertion::lessThan($recipient, $jwe->countRecipients());
        $protectedHeaders = $jwe->getSharedProtectedHeaders();
        $headers = array_merge(
            $jwe->getRecipient($recipient)->getHeaders(),
            $jwe->getSharedHeaders()
        );
        $this->checkHeaders($protectedHeaders, $headers, $checked_claims);
    }

    /**
     * @param JWTInterface $jwt
     *
     * @return string[]
     */
    private function checkClaims(JWTInterface $jwt): array
    {
        $checked_claims = [];
        $claims = json_decode($jwt->getPayload(), true);
        if (!is_array($claims)) {
            throw new \InvalidArgumentException('The payload is does not contain claims.');
        }

        foreach ($this->claimCheckers as $claimChecker) {
            $checked_claims = array_merge(
                $checked_claims,
                $claimChecker->checkClaim($claims)
            );
        }

        return $checked_claims;
    }

    /**
     * @param array $protectedHeaders
     * @param array $headers
     * @param array $checked_claims
     */
    private function checkHeaders(array $protectedHeaders, array $headers, array $checked_claims)
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
