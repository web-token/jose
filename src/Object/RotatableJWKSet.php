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

use Assert\Assertion;

/**
 * Class RotatableJWKSet.
 */
final class RotatableJWKSet extends StorableJWKSet implements RotatableJWKSetInterface
{
    /**
     * @var int
     */
    protected $ttl;

    /**
     * RotatableJWKSet constructor.
     *
     * @param string $filename
     * @param array  $parameters
     * @param int    $nb_keys
     * @param int    $ttl
     */
    public function __construct($filename, array $parameters, $nb_keys, $ttl)
    {
        Assertion::integer($ttl);
        Assertion::greaterThan($ttl, 0, 'The parameter TTL must be at least 0.');
        $this->ttl = $ttl;
        parent::__construct($filename, $parameters, $nb_keys);
    }

    /**
     * @return \Jose\Object\JWKSetInterface
     */
    protected function getJWKSet()
    {
        if (file_exists($this->getFilename())) {
            $mtime = filemtime($this->getFilename());
            if ($mtime + $this->ttl <= time()) {
                $keys = $this->jwkset->getKeys();
                unset($keys[count($keys) - 1]);
                $this->jwkset = new JWKSet();
                $this->jwkset->addKey($this->createJWK());
                foreach ($keys as $key) {
                    $this->jwkset->addKey($key);
                }
                $this->save();
            }
        }

        return parent::getJWKSet();
    }
}
