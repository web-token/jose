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
 * This interface is used to manage all compression methods.
 */
interface CompressionManagerInterface
{
    /**
     * This method will try to find a CompressionInterface object able to support the compression method.
     *
     * @param string $name The name of the compression method
     *
     * @return \Jose\Compression\CompressionInterface|null If the compression handler is supported, return CompressionInterface object, else null
     */
    public function getCompressionAlgorithm($name);

    /**
     * @param \Jose\Compression\CompressionInterface $compression_algorithm
     */
    public function addCompressionAlgorithm(CompressionInterface $compression_algorithm);
}
