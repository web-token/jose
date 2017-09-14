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

use Jose\Component\Core\Converter\JsonConverterInterface;
use Jose\Component\Core\JWTInterface;

/**
 * Class ClaimCheckerManager.
 */
final class ClaimCheckerManager
{
    /**
     * @var JsonConverterInterface
     */
    private $payloadEncoder;

    /**
     * @var ClaimCheckerInterface[]
     */
    private $checkers = [];

    /**
     * ClaimCheckerManager constructor.
     *
     * @param JsonConverterInterface  $payloadEncoder
     * @param ClaimCheckerInterface[] $checkers
     */
    public function __construct(JsonConverterInterface $payloadEncoder, array $checkers)
    {
        $this->payloadEncoder = $payloadEncoder;
        foreach ($checkers as $checker) {
            $this->add($checker);
        }
    }

    /**
     * @param ClaimCheckerInterface $checker
     */
    private function add(ClaimCheckerInterface $checker)
    {
        $claim = $checker->supportedClaim();
        if (array_key_exists($claim, $this->checkers)) {
            throw new \InvalidArgumentException(sprintf('The claim checker "%s" is already supported.', $claim));
        }

        $this->checkers[$claim] = $checker;
    }

    /**
     * @param JWTInterface $jwt
     */
    public function check(JWTInterface $jwt)
    {
        $claims = $this->payloadEncoder->decode($jwt->getPayload());
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
