<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

/**
 * Class RotatableJWKSet.
 */
final class RotatableJWKSet extends StorableJWKSet implements RotatableInterface
{
    /**
     * Interval at which keys should be rotated.
     *
     * @var int|null
     */
    private $interval;

    /**
     * RotatableJWKSet constructor.
     *
     * @param string   $filename
     * @param array    $parameters
     * @param int      $nb_keys
     * @param int|null $interval
     */
    public function __construct($filename, array $parameters, $nb_keys, $interval = null)
    {
        parent::__construct($filename, $parameters, $nb_keys);

        $this->interval = $interval;
    }

    /**
     * {@inheritdoc}
     */
    public function getJWKSet()
    {
        // Check if we need to rotate keys upon every interaction with the underlying JWK set
        $this->rotateIfNeeded();

        return parent::getJWKSet();
    }

    /**
     * {@inheritdoc}
     */
    public function rotate()
    {
        $jwkset = parent::getJWKSet();

        // Remove last key in set
        $jwkset->removeKey($jwkset->countKeys() - 1);

        // Prepend new key to set
        $jwkset->prependKey($this->createJWK());

        // Save new key set
        $this->saveObject($jwkset);
    }

    /**
     * Rotate key set if last modification time is due.
     */
    private function rotateIfNeeded()
    {
        if (isset($this->interval) && $this->interval >= 0) {
            $modificationTime = $this->getLastModificationTime();

            if (null === $modificationTime) {
                $this->regen();
            } elseif (($modificationTime + $this->interval) < time()) {
                $this->rotate();
            }
        }
    }
}
