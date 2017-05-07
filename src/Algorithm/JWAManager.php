<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm;

/**
 * Class JWAManager.
 */
final class JWAManager
{
    /**
     * @var array
     */
    protected $algorithms = [];

    /**
     * @param string $algorithm The algorithm
     *
     * @return bool Returns true if the algorithm is supported
     */
    public function isAlgorithmSupported(string $algorithm): bool
    {
        return null !== $this->getAlgorithm($algorithm);
    }

    /**
     * @return JWAInterface[] Returns the list of supported algorithms
     */
    public function getAlgorithms(): array
    {
        return $this->algorithms;
    }

    /**
     * @return string[] Returns the list of names of supported algorithms
     */
    public function listAlgorithms(): array
    {
        return array_keys($this->getAlgorithms());
    }

    /**
     * @param string $algorithm The algorithm
     *
     * @return JWAInterface|null Returns JWAInterface object if the algorithm is supported, else null
     */
    public function getAlgorithm(string $algorithm): ?JWAInterface
    {
        return array_key_exists($algorithm, $this->algorithms) ? $this->algorithms[$algorithm] : null;
    }

    /**
     * @param JWAInterface $algorithm
     */
    public function addAlgorithm(JWAInterface $algorithm)
    {
        if (!$this->isAlgorithmSupported($algorithm->getAlgorithmName())) {
            $this->algorithms[$algorithm->getAlgorithmName()] = $algorithm;
        }
    }
}
