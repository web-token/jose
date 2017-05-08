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

/**
 * Class JWT.
 */
trait JWT
{
    /**
     * @var mixed|null
     */
    private $payload = null;

    /**
     * Returns the payload of the JWT.
     *
     * @return string                       Payload
     * @return array                        Payload
     * @return JWKInterface    Payload
     * @return JWKSetInterface Payload
     * @return mixed                        Payload
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * @param mixed $payload
     *
     * @internal
     *
     * @return JWTInterface
     */
    public function withPayload($payload): JWTInterface
    {
        $jwt = clone $this;
        $jwt->payload = $payload;

        return $jwt;
    }

    /**
     * Returns the value of the payload of the specified key.
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
        if (is_array($this->payload)) {
            return $this->payload;
        }
        throw new \InvalidArgumentException('The payload does not contain claims.');
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
