<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Checker;

use Assert\Assertion;
use Jose\Object\JWTInterface;

abstract class SubjectChecker implements ClaimCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWTInterface $jwt)
    {
        if (!$jwt->hasClaim('sub')) {
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
    abstract protected function isSubjectAllowed($subject);
}
