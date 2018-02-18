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

/**
 * Class JWAManager.
 */
final class JWAManager implements JWAManagerInterface
{
    /**
     * @var array
     */
    protected $algorithms = [];

    /**
     * {@inheritdoc}
     */
    public function isAlgorithmSupported($algorithm)
    {
        return null !== $this->getAlgorithm($algorithm);
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithms()
    {
        return $this->algorithms;
    }

    /**
     * {@inheritdoc}
     */
    public function listAlgorithms()
    {
        return array_keys($this->getAlgorithms());
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm($algorithm)
    {
        return array_key_exists($algorithm, $this->algorithms) ? $this->algorithms[$algorithm] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function addAlgorithm(JWAInterface $algorithm)
    {
        if (!$this->isAlgorithmSupported($algorithm->getAlgorithmName())) {
            $this->algorithms[$algorithm->getAlgorithmName()] = $algorithm;
        }
    }

    /**
     * [@inheritdoc}.
     */
    public function removeAlgorithm($algorithm)
    {
        if ($algorithm instanceof JWAInterface) {
            $name = $algorithm->getAlgorithmName();
        } elseif (is_string($algorithm)) {
            $name = $algorithm;
        } else {
            throw new \InvalidArgumentException('Argument must be a string or a JWAInterface object.');
        }
        if (array_key_exists($name, $this->algorithms)) {
            unset($this->algorithms[$name]);
        }
    }
}
