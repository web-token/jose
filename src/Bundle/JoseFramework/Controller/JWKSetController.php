<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Controller;

use Jose\Component\Core\JWKSet;
use Symfony\Component\HttpFoundation\Response;

final class JWKSetController
{
    /**
     * @var JWKSet
     */
    private $jwkset;

    /**
     * @var int
     */
    private $maxAge;

    /**
     * JWKSetController constructor.
     *
     * @param JWKSet $jwkset
     * @param int    $maxAge
     */
    public function __construct(JWKSet $jwkset, int$maxAge)
    {
        $this->jwkset = $jwkset;
        $this->maxAge = $maxAge;
    }

    /**
     * @return Response
     */
    public function __invoke(): Response
    {
        return new Response(
            json_encode($this->jwkset),
            Response::HTTP_OK,
            [
                'Content-Type'  => 'application/jwk-set+json; charset=UTF-8',
               'Cache-Control' =>  sprintf('public, max-age=%d, must-revalidate, no-transform', $this->maxAge)
            ]
        );
    }
}
