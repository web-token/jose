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
 * This interface is used by all compression methods.
 */
interface CompressionInterface
{
    /**
     * @return string Return the name of the method
     */
    public function getMethodName();

    /**
     * Compress the data.
     *
     * @param string $data The data to compress
     *
     * @throws \RuntimeException
     *
     * @return string The compressed data
     */
    public function compress($data);

    /**
     * Uncompress the data.
     *
     * @param string $data The data to uncompress
     *
     * @throws \RuntimeException
     *
     * @return string The uncompressed data
     */
    public function uncompress($data);
}
