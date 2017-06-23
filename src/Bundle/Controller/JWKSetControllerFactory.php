<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle\Controller;

use Jose\Component\Core\JWKSetInterface;

final class JWKSetControllerFactory
{
    /**
     * @param \Jose\Component\Core\JWKSetInterface $issuer_discovery
     *
     * @return \SpomkyLabs\JoseBundle\Controller\JWKSetController
     */
    public function createJWKSetController(JWKSetInterface $jwkset)
    {
        return new JWKSetController($jwkset);
    }
}
