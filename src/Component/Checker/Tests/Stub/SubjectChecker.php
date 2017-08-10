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

use Jose\Component\Checker\ClaimCheckerInterface;

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
        if (!is_string($sub)) {
            throw new \InvalidArgumentException('The claim "sub" must be an string.');
        }
        if (!$this->isSubjectAllowed($sub)) {
            throw new \InvalidArgumentException(sprintf('The subject "%s" is not allowed.', $sub));
        }

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
