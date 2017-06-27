<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle\Service;

use Assert\Assertion;
use Jose\Checker\ClaimCheckerInterface;
use Jose\Checker\HeaderCheckerInterface;

final class CheckerManager
{
    /**
     * @var \Jose\Checker\ClaimCheckerInterface[]
     */
    private $claim_checkers = [];

    /**
     * @var \Jose\Checker\HeaderCheckerInterface[]
     */
    private $header_checkers = [];

    /**
     * @param \Jose\Checker\ClaimCheckerInterface $checker
     * @param string                              $alias
     */
    public function addClaimChecker(ClaimCheckerInterface $checker, $alias)
    {
        if (!array_key_exists($alias, $this->claim_checkers)) {
            $this->claim_checkers[$alias] = $checker;
        }
    }

    /**
     * @param \Jose\Checker\HeaderCheckerInterface $checker
     * @param string                               $alias
     */
    public function addHeaderChecker(HeaderCheckerInterface $checker, $alias)
    {
        if (!array_key_exists($alias, $this->header_checkers)) {
            $this->header_checkers[$alias] = $checker;
        }
    }

    /**
     * @param string[] $selected_claim_checkers
     *
     * @return \Jose\Checker\ClaimCheckerInterface[]
     */
    public function getSelectedClaimChecker(array $selected_claim_checkers)
    {
        $result = [];
        foreach ($selected_claim_checkers as $alias) {
            Assertion::keyExists($this->claim_checkers, $alias, sprintf('The claim checker alias "%s" is not supported.', $alias));
            $result[] = $this->claim_checkers[$alias];
        }

        return $result;
    }

    /**
     * @param string[] $selected_header_checkers
     *
     * @return \Jose\Checker\HeaderCheckerInterface[]
     */
    public function getSelectedHeaderChecker(array $selected_header_checkers)
    {
        $result = [];
        foreach ($selected_header_checkers as $alias) {
            Assertion::keyExists($this->header_checkers, $alias, sprintf('The header checker alias "%s" is not supported.', $alias));
            $result[] = $this->header_checkers[$alias];
        }

        return $result;
    }
}
