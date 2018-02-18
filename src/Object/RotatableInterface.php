<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

/**
 * Interface RotatableJInterface.
 */
interface RotatableInterface extends StorableInterface
{
    /**
     * This method create a new key and add it to the key set
     * The oldest key is removed.
     */
    public function rotate();
}
