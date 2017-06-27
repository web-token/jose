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
use Jose\Component\Core\JWAInterface;

final class AlgorithmManager
{
    /**
     * @var JWAInterface[]
     */
    private $algorithms = [];

    /**
     * @param JWAInterface $algorithm
     */
    public function addAlgorithm(JWAInterface $algorithm)
    {
        $name = $algorithm->getAlgorithmName();
        if (!array_key_exists($name, $this->algorithms)) {
            $this->algorithms[$name] = $algorithm;
        }
    }

    /**
     * @param string[] $selected_algorithms
     *
     * @return JWAInterface[]
     */
    public function getSelectedAlgorithmMethods(array $selected_algorithms)
    {
        $result = [];
        foreach ($selected_algorithms as $algorithm) {
            Assertion::keyExists($this->algorithms, $algorithm, sprintf('The algorithm "%s" is not supported.', $algorithm));
            $result[] = $this->algorithms[$algorithm];
        }

        return $result;
    }
}
