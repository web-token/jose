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

use Jose\Algorithm\JWAManagerInterface;

trait HasJWAManager
{
    /**
     * @var \Jose\Algorithm\JWAManagerInterface
     */
    private $jwa_manager;

    /**
     * @param \Jose\Algorithm\JWAManagerInterface $jwa_manager
     */
    private function setJWAManager(JWAManagerInterface $jwa_manager)
    {
        $this->jwa_manager = $jwa_manager;
    }

    /**
     * @return \Jose\Algorithm\JWAManagerInterface
     */
    protected function getJWAManager()
    {
        return $this->jwa_manager;
    }
}
