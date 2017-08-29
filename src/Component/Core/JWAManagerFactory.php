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

namespace Jose\Component\Core;

final class JWAManagerFactory
{
    /**
     * @var array
     */
    private $algorithms;

    /**
     * @param string       $alias
     * @param JWAInterface $algorithm
     */
    public function add(string $alias, JWAInterface $algorithm)
    {
        $this->algorithms[$alias] = $algorithm;
    }

    /**
     * @param string[] $aliases
     *
     * @return JWAManager
     */
    public function create(array $aliases): JWAManager
    {
        $algorithms = [];
        foreach ($aliases as $alias) {
            if (array_key_exists($alias, $this->algorithms)) {
                $algorithms[] = $this->algorithms[$alias];
            } else {
                throw new \InvalidArgumentException(sprintf('The algorithm with the alias "%s" is not supported.', $alias));
            }
        }

        return JWAManager::create($algorithms);
    }
}
