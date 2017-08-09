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
    public function checkClaim(array $claims): array
    {
        if (!array_key_exists('aud', $claims)) {
            return [];
        }

        $audience = $claims['aud'];
        if (is_string($audience) && $audience !== $this->getAudience()) {
            throw new \InvalidArgumentException('Bad audience.');
        } elseif (!is_array($audience) || !in_array($this->getAudience(), $audience)) {
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
