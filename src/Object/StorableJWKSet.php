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
use Base64Url\Base64Url;
use Jose\Factory\JWKFactory;

/**
 * Class StorableJWKSet.
 */
final class StorableJWKSet implements StorableJWKSetInterface
{
    /**
     * @var \Jose\Object\JWKSetInterface
     */
    private $jwkset;

    /**
     * @var string
     */
    private $filename;

    /**
     * @var array
     */
    private $parameters;

    /**
     * @var array
     */
    private $nb_keys;

    /**
     * StorableJWKSet constructor.
     *
     * @param string $filename
     * @param array  $parameters
     * @param int    $nb_keys
     */
    public function __construct($filename, array $parameters, $nb_keys)
    {
        Assertion::directory(dirname($filename), 'The selected directory does not exist.');
        Assertion::writeable(dirname($filename), 'The selected directory is not writable.');
        Assertion::integer($nb_keys, 'The key set must contain at least one key.');
        Assertion::greaterThan($nb_keys, 0, 'The key set must contain at least one key.');
        $this->filename = $filename;
        $this->parameters = $parameters;
        $this->nb_keys = $nb_keys;
    }

    /**
     * {@inheritdoc}
     */
    public function getFilename()
    {
        return $this->filename;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return $this->getJWKSet()->jsonSerialize();
    }

    /**
     * @return \Jose\Object\JWKSetInterface
     */
    private function getJWKSet()
    {
        if (null === $this->jwkset) {
            $this->loadJWKSet();
        }

        return $this->jwkset;
    }

    private function loadJWKSet()
    {
        if (file_exists($this->filename)) {
            $content = file_get_contents($this->filename);
            if (false === $content) {
                $this->createJWKSet();
            }
            $content = json_decode($content, true);
            if (!is_array($content)) {
                $this->createJWKSet();
            }
            $this->jwkset = new JWKSet($content);
        } else {
            $this->createJWKSet();
        }
    }

    private function createJWKSet()
    {
        /*$data = JWKFactory::createKey($this->parameters)->getAll();
        $this->jwkset = JWKFactory::createFromValues($data);

        file_put_contents(
            $this->filename,
            json_encode($this->jwkset)
        );*/
    }
}
