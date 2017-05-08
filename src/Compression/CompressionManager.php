<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Compression;

/**
 * Compression algorithm manager.
 */
final class CompressionManager
{
    /**
     * @var \Jose\Compression\CompressionInterface[]
     */
    protected $compression_algorithms = [];

    /**
     * @param \Jose\Compression\CompressionInterface $compression_algorithm
     */
    public function addCompressionAlgorithm(CompressionInterface $compression_algorithm)
    {
        $this->compression_algorithms[$compression_algorithm->name()] = $compression_algorithm;
    }

    /**
     * This method will try to find a CompressionInterface object able to support the compression method.
     *
     * @param string $name The name of the compression method
     *
     * @return \Jose\Compression\CompressionInterface|null If the compression handler is supported, return CompressionInterface object, else null
     */
    public function getCompressionAlgorithm($name)
    {
        return array_key_exists($name, $this->compression_algorithms) ? $this->compression_algorithms[$name] : null;
    }
}
