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

use Jose\Component\Core\JWT;

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
    public function checkClaim(JWT $jwt): array
    {
        if (! $jwt->hasClaim('aud')) {
            return [];
        }

        $audience = $jwt->getClaim('aud');
        if (! is_array($audience) || ! in_array($this->getAudience(), $audience)) {
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
