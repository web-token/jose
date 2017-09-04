<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Controller;

use Jose\Component\Core\JWKSet;

final class JWKSetControllerFactory
{
    /**
     * @param JWKSet $jwkset
     * @param int    $maxAge
     *
     * @return JWKSetController
     */
    public function create(JWKSet $jwkset, int $maxAge): JWKSetController
    {
        return new JWKSetController($jwkset, $maxAge);
    }
}
