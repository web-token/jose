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
 * Class JWT.
 */
abstract class JWT
{
    /**
     * @var mixed|null
     */
    private $payload = null;

    /**
     * Returns the payload of the JWT.
     *
     * @return mixed|null
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * @param mixed $payload
     *
     * @return JWT
     */
    public function withPayload($payload): JWT
    {
        $jwt = clone $this;
        $jwt->payload = $payload;

        return $jwt;
    }

    /**
     * Returns the value of the claim at index $key.
     *
     * @param string $key The key
     *
     * @return mixed|null Payload value
     */
    public function getClaim(string $key)
    {
        if ($this->hasClaim($key)) {
            return $this->payload[$key];
        }
        throw new \InvalidArgumentException(sprintf('The payload does not contain claim "%s".', $key));
    }

    /**
     * Returns the claims.
     *
     * @return array Payload value
     */
    public function getClaims(): array
    {
        if (!$this->hasClaims()) {
            throw new \InvalidArgumentException('The payload does not contain claims.');
        }

        return $this->payload;
    }

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasClaim(string $key): bool
    {
        return $this->hasClaims() && array_key_exists($key, $this->payload);
    }

    /**
     * @return bool
     */
    public function hasClaims(): bool
    {
        return is_array($this->payload);
    }
}
