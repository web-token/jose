<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core;

/**
 * Interface JWTInterface.
 */
interface JWTInterface
{
    /**
     * Returns the payload of the JWT.
     *
     * @return mixed|null
     */
    public function getPayload();

    /**
     * Returns the value of the claim at index $key.
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
