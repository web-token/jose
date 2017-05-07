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

use Jose\Algorithm\JWAManager;

trait HasJWAManager
{
    /**
     * @var JWAManager
     */
    private $jwa_manager;

    /**
     * @param JWAManager $jwa_manager
     */
    private function setJWAManager(JWAManager $jwa_manager)
    {
        $this->jwa_manager = $jwa_manager;
    }

    /**
     * @return JWAManager
     */
    protected function getJWAManager()
    {
        return $this->jwa_manager;
    }
}
