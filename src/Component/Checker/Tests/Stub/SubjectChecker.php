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
use Jose\Component\Core\JWT;

final class SubjectChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWT $jwt): array
    {
        if (! $jwt->hasClaim('sub')) {
            return [];
        }

        $subject = $jwt->getClaim('sub');
        Assertion::true($this->isSubjectAllowed($subject), sprintf('The subject "%s" is not allowed.', $subject));

        return ['sub'];
    }

    /**
     * @param string $subject
     *
     * @return bool
     */
    private function isSubjectAllowed(string $subject): bool
    {
        return in_array($subject, ['SUB1', 'SUB2']);
    }
}
