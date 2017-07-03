<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle\Controller;

use Jose\Component\Core\JWKSet;

final class JWKSetControllerFactory
{
    /**
     * @param \Jose\Component\Core\JWKSet $issuer_discovery
     *
     * @return \SpomkyLabs\JoseBundle\Controller\JWKSetController
     */
    public function createJWKSetController(JWKSet $jwkset)
    {
        return new JWKSetController($jwkset);
    }
}
