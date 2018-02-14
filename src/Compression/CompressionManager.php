<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Compression;

/**
 * Compression algorithm manager.
 */
final class CompressionManager implements CompressionManagerInterface
{
    /**
     * @var \Jose\Compression\CompressionInterface[]
     */
    protected $compression_algorithms = [];

    /**
     * {@inheritdoc}
     */
    public function addCompressionAlgorithm(CompressionInterface $compression_algorithm)
    {
        $this->compression_algorithms[$compression_algorithm->getMethodName()] = $compression_algorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function getCompressionAlgorithm($name)
    {
        return array_key_exists($name, $this->compression_algorithms) ? $this->compression_algorithms[$name] : null;
    }
}
