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

namespace Jose\Component\Checker\Tests\Stub;

use Assert\Assertion;
use Jose\Component\Checker\ClaimCheckerInterface;
use Jose\Component\Core\JWTInterface;

final class SubjectChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(array $claims): array
    {
        if (!array_key_exists('sub', $claims)) {
            return [];
        }

        $sub = $claims['sub'];
        Assertion::string($sub, 'Invalid claim "sub". The value must be a string.');
        Assertion::true($this->isSubjectAllowed($sub), sprintf('The subject "%s" is not allowed.', $sub));

        return ['sub'];
    }

    /**
     * @param string $sub
     *
     * @return bool
     */
    private function isSubjectAllowed(string $sub): bool
    {
        return in_array($sub, ['SUB1', 'SUB2']);
    }
}
