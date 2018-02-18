<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Behaviour;

use Jose\Compression\CompressionManagerInterface;

trait HasCompressionManager
{
    /**
     * @var \Jose\Compression\CompressionManagerInterface
     */
    private $compression_manager;

    /**
     * @param \Jose\Compression\CompressionManagerInterface $compression_manager
     */
    private function setCompressionManager(CompressionManagerInterface $compression_manager)
    {
        $this->compression_manager = $compression_manager;
    }

    /**
     * @return \Jose\Compression\CompressionManagerInterface
     */
    protected function getCompressionManager()
    {
        return $this->compression_manager;
    }
}
