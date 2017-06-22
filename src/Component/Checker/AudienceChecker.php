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
use Jose\Object\JWS;

final class AudienceChecker implements ClaimCheckerInterface
{
    /**
     * @var string
     */
    private $audience;

    /**
     * AudienceChecker constructor.
     *
     * @param string $audience
     */
    public function __construct(string $audience)
    {
        $this->audience = $audience;
    }

    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWS $jwt): array
    {
        if (!$jwt->hasClaim('aud')) {
            return [];
        }

        $audience = $jwt->getClaim('aud');
        if (is_string($audience)) {
            Assertion::eq($audience, $this->getAudience(), 'Bad audience.');
        } elseif (is_array($audience)) {
            Assertion::inArray($this->getAudience(), $audience, 'Bad audience.');
        } else {
            throw new \InvalidArgumentException('Bad audience.');
        }

        return ['aud'];
    }

    /**
     * @return string
     */
    public function getAudience(): string
    {
        return $this->audience;
    }
}
