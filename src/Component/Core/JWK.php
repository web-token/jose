<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core;

use Assert\Assertion;
use Base64Url\Base64Url;

/**
 * Class JWK.
 */
final class JWK implements \JsonSerializable
{
    /**
     * @var array
     */
    private $values = [];

    /**
     * JWK constructor.
     *
     * @param array $values
     */
    private function __construct(array $values = [])
    {
        Assertion::keyExists($values, 'kty', 'The parameter "kty" is mandatory.');

        $this->values = $values;
    }

    /**
     * @param array $values
     *
     * @return JWK
     */
    public static function create(array $values = []): JWK
    {
        return new self($values);
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return $this->getAll();
    }

    /**
     * Get the value with a specific key.
     *
     * @param string $key The key
     *
     * @throws \InvalidArgumentException
     *
     * @return mixed|null The value
     */
    public function get(string $key)
    {
        if ($this->has($key)) {
            return $this->values[$key];
        }
        throw new \InvalidArgumentException(sprintf('The value identified by "%s" does not exist.', $key));
    }

    /**
     * Returns true if the JWK has the value identified by.
     *
     * @param string $key The key
     *
     * @return bool
     */
    public function has(string $key): bool
    {
        return array_key_exists($key, $this->getAll());
    }

    /**
     * Get all values stored in the JWK object.
     *
     * @return array Values of the JWK object
     */
    public function getAll(): array
    {
        return $this->values;
    }

    /**
     * Returns the thumbprint of the key.
     *
     * @see https://tools.ietf.org/html/rfc7638
     *
     * @param string $hash_algorithm
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    public function thumbprint(string $hash_algorithm): string
    {
        Assertion::inArray($hash_algorithm, hash_algos(), sprintf('Hash algorithm "%s" is not supported', $hash_algorithm));

        $values = array_intersect_key($this->getAll(), array_flip(['kty', 'n', 'e', 'crv', 'x', 'y', 'k']));
        ksort($values);
        $input = json_encode($values);

        return Base64Url::encode(hash($hash_algorithm, $input, true));
    }

    /**
     * @return JWK
     */
    public function toPublic(): JWK
    {
        $values = $this->getAll();
        $values = array_diff_key($values, array_flip(['p', 'd', 'q', 'dp', 'dq', 'qi']));

        return new self($values);
    }
}
