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
        $checkedClaims = $this->checkClaims($jws);
        if ($signature > $jws->countSignatures()) {
            throw new \InvalidArgumentException('Unknown signature index.');
        }
        $protectedHeaders = $jws->getSignature($signature)->getProtectedHeaders();
        $headers = $jws->getSignature($signature)->getHeaders();
        $this->checkHeaders($protectedHeaders, $headers, $checkedClaims);
    }

    /**
     * @param JWE $jwe
     * @param int $recipient
     */
    public function checkJWE(JWE $jwe, int $recipient)
    {
        $checkedClaims = $this->checkClaims($jwe);
        if ($recipient > $jwe->countRecipients()) {
            throw new \InvalidArgumentException('Unknown recipient index.');
        }
        $protectedHeaders = $jwe->getSharedProtectedHeaders();
        $headers = array_merge(
            $jwe->getRecipient($recipient)->getHeaders(),
            $jwe->getSharedHeaders()
        );
        $this->checkHeaders($protectedHeaders, $headers, $checkedClaims);
    }

    /**
     * @param JWTInterface $jwt
     *
     * @return string[]
     */
    private function checkClaims(JWTInterface $jwt): array
    {
        $checkedClaims = [];
        $claims = json_decode($jwt->getPayload(), true);
        if (!is_array($claims)) {
            throw new \InvalidArgumentException('The payload is does not contain claims.');
        }

        foreach ($this->claimCheckers as $claimChecker) {
            $checkedClaims = array_merge(
                $checkedClaims,
                $claimChecker->checkClaim($claims)
            );
        }

        return $checkedClaims;
    }

    /**
     * @param array $protectedHeaders
     * @param array $headers
     * @param array $checkedClaims
     */
    private function checkHeaders(array $protectedHeaders, array $headers, array $checkedClaims)
    {
        foreach ($this->headerCheckers as $headerChecker) {
            $headerChecker->checkHeader($protectedHeaders, $headers, $checkedClaims);
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
