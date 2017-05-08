<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Behaviour;

use Jose\Compression\CompressionManager;

trait HasCompressionManager
{
    /**
     * @var CompressionManager
     */
    private $compression_manager;

    /**
     * @param CompressionManager $compression_manager
     */
    private function setCompressionManager(CompressionManager $compression_manager)
    {
        $this->compression_manager = $compression_manager;
    }

    /**
     * @return CompressionManager
     */
    protected function getCompressionManager()
    {
        return $this->compression_manager;
    }
}
