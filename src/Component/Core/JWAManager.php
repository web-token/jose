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
 * Class JWAManager.
 */
final class JWAManager
{
    /**
     * @var array
     */
    private $algorithms = [];

    /**
     * JWAManager constructor.
     *
     * @param JWAInterface[] $algorithms
     */
    private function __construct(array $algorithms)
    {
        foreach ($algorithms as $algorithm) {
            $this->add($algorithm);
        }
    }

    /**
     * @param JWAInterface[] $algorithms
     *
     * @return JWAManager
     */
    public static function create(array $algorithms): JWAManager
    {
        return new self($algorithms);
    }

    /**
     * @param string $algorithm The algorithm
     *
     * @return bool Returns true if the algorithm is supported
     */
    public function has(string $algorithm): bool
    {
        return array_key_exists($algorithm, $this->algorithms);
    }

    /**
     * @return string[] Returns the list of names of supported algorithms
     */
    public function list(): array
    {
        return array_keys($this->algorithms);
    }

    /**
     * @param string $algorithm The algorithm
     *
     * @return JWAInterface Returns JWAInterface object if the algorithm is supported, else null
     */
    public function get(string $algorithm): JWAInterface
    {
        if (!$this->has($algorithm)) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is not supported.', $algorithm));
        }

        return $this->algorithms[$algorithm];
    }

    /**
     * @param JWAInterface $algorithm
     */
    private function add(JWAInterface $algorithm)
    {
        $name = $algorithm->name();
        if ($this->has($name)) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is already supported.', $name));
        }

        $this->algorithms[$name] = $algorithm;
    }
}
