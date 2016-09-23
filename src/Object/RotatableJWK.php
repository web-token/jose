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
 * Class RotatableJWK.
 */
final class RotatableJWK extends StorableJWK implements RotatableJWKInterface
{
    /**
     * @var int
     */
    protected $ttl;

    /**
     * @param string $filename
     * @param int    $ttl
     */
    public function __construct($filename, array $parameters, $ttl)
    {
        Assertion::integer($ttl);
        Assertion::greaterThan($ttl, 0, 'The parameter TTL must be at least 0.');
        $this->ttl = $ttl;
        parent::__construct($filename, $parameters);
    }

    /**
     * @return \Jose\Object\JWKInterface
     */
    protected function getJWK()
    {
        if (file_exists($this->getFilename())) {
            $mtime = filemtime($this->getFilename());
            if ($mtime + $this->ttl <= time()) {
                unlink($this->getFilename());
            }
        }

        return parent::getJWK();
    }
}
