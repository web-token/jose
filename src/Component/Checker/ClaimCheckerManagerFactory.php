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

final class ClaimCheckerManagerFactory
{
    /**
     * @var ClaimCheckerInterface[]
     */
    private $checkers = [];

    /**
     * @param string[] $aliases
     *
     * @return ClaimCheckerManager
     */
    public function create(array $aliases): ClaimCheckerManager
    {
        $checkers = [];
        foreach ($aliases as $alias) {
            if (array_key_exists($alias, $this->checkers)) {
                $checkers[] = $this->checkers[$alias];
            } else {
                throw new \InvalidArgumentException(sprintf('The claim checker with the alias "%s" is not supported.', $alias));
            }
        }

        return ClaimCheckerManager::create($checkers);
    }

    /**
     * @param string $alias
     *
     * @param ClaimCheckerInterface $checker
     */
    public function add(string $alias, ClaimCheckerInterface $checker)
    {
        $this->checkers[$alias] = $checker;
    }

    /**
     * @return string[]
     */
    public function aliases(): array
    {
        return array_keys($this->checkers);
    }
}
