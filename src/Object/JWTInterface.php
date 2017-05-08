<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

interface JWTInterface
{
    /**
     * Returns the payload of the JWT.
     *
     * @return string                       Payload
     * @return array                        Payload
     * @return JWKInterface    Payload
     * @return JWKSetInterface Payload
     * @return mixed                        Payload
     */
    public function getPayload();

    /**
     * @param mixed $payload
     *
     * @internal
     *
     * @return JWTInterface
     */
    public function withPayload($payload): JWTInterface;

    /**
     * Returns the value of the payload of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Payload value
     */
    public function getClaim(string $key);

    /**
     * Returns the claims.
     *
     * @return array Payload value
     */
    public function getClaims(): array;

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasClaim(string $key): bool;

    /**
     * @return bool
     */
    public function hasClaims(): bool;
}
