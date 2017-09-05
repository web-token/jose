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

namespace Jose\Component\Signature;

use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\JWAManager;
use Jose\Component\Core\JWKSet;

/**
 * Class able to load JWS and verify signatures and headers.
 */
final class JWSLoader
{
    /**
     * @var HeaderCheckerManager
     */
    private $headerCheckerManager;

    /**
     * @var Verifier
     */
    private $verifier;

    /**
     * JWSLoader constructor.
     *
     * @param JWAManager $signatureAlgorithmManager
     * @param HeaderCheckerManager $headerCheckerManager
     */
    public function __construct(JWAManager $signatureAlgorithmManager, HeaderCheckerManager $headerCheckerManager)
    {
        $this->verifier = new Verifier($signatureAlgorithmManager);
        $this->headerCheckerManager = $headerCheckerManager;
    }

    /**
     * @param string $input
     * @param JWKSet $keyset
     * @param null|string $detachedPayload
     *
     * @return JWS
     */
    public function load(string $input, JWKSet $keyset, ?string $detachedPayload = null): JWS
    {
        $jws = JWSParser::parse($input);
        $index = null;
        $this->verifier->verifyWithKeySet($jws, $keyset, $detachedPayload, $index);
        $this->headerCheckerManager->checkJWS($jws, $index);

        return $jws;
    }
}
