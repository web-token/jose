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
 * Class StorableJWK.
 */
final class StorableJWK implements StorableJWKInterface
{
    /**
     * @var \Jose\Object\JWKInterface
     */
    private $jwk;

    /**
     * @var string
     */
    private $filename;

    /**
     * @var array
     */
    private $parameters;

    /**
     * RotatableJWK constructor.
     *
     * @param string $filename
     * @param array  $parameters
     */
    public function __construct($filename, array $parameters)
    {
        Assertion::directory(dirname($filename), 'The selected directory does not exist.');
        Assertion::writeable(dirname($filename), 'The selected directory is not writable.');
        $this->filename = $filename;
        $this->parameters = $parameters;
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
    public function getAll()
    {
        return $this->getJWK()->getAll();
    }

    /**
     * {@inheritdoc}
     */
    public function get($key)
    {
        return $this->getJWK()->get($key);
    }

    /**
     * {@inheritdoc}
     */
    public function has($key)
    {
        return $this->getJWK()->has($key);
    }

    /**
     * {@inheritdoc}
     */
    public function thumbprint($hash_algorithm)
    {
        return $this->getJWK()->thumbprint($hash_algorithm);
    }

    /**
     * {@inheritdoc}
     */
    public function toPublic()
    {
        return $this->getJWK()->toPublic();
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return $this->getJWK()->jsonSerialize();
    }

    /**
     * @return \Jose\Object\JWKInterface
     */
    private function getJWK()
    {
        if (null === $this->jwk) {
            $this->loadJWK();
        }

        return $this->jwk;
    }

    private function loadJWK()
    {
        if (file_exists($this->filename)) {
            $content = file_get_contents($this->filename);
            if (false === $content) {
                $this->createJWK();
            }
            $content = json_decode($content, true);
            if (!is_array($content)) {
                $this->createJWK();
            }
            $this->jwk = new JWK($content);
        } else {
            $this->createJWK();
        }
    }

    private function createJWK()
    {
        $data = JWKFactory::createKey($this->parameters)->getAll();
        $data['kid'] = Base64Url::encode(random_bytes(64));
        $this->jwk = JWKFactory::createFromValues($data);

        file_put_contents(
            $this->filename,
            json_encode($this->jwk)
        );
    }
}
