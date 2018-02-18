<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm;

interface JWAManagerInterface
{
    /**
     * @param string $algorithm The algorithm
     *
     * @return bool Returns true if the algorithm is supported
     */
    public function isAlgorithmSupported($algorithm);

    /**
     * @param string $algorithm The algorithm
     *
     * @return \Jose\Algorithm\JWAInterface|null Returns JWAInterface object if the algorithm is supported, else null
     */
    public function getAlgorithm($algorithm);

    /**
     * @return \Jose\Algorithm\JWAInterface[] Returns the list of supported algorithms
     */
    public function getAlgorithms();

    /**
     * @return string[] Returns the list of names of supported algorithms
     */
    public function listAlgorithms();

    /**
     * @param \Jose\Algorithm\JWAInterface $algorithm
     */
    public function addAlgorithm(JWAInterface $algorithm);

    /**
     * @param string $algorithm
     *
     * @throws \InvalidArgumentException
     */
    public function removeAlgorithm($algorithm);
}
