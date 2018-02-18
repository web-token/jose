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

use Base64Url\Base64Url;
use Jose\Factory\JWKFactory;

/**
 * Class StorableJWK.
 */
class StorableJWK implements StorableInterface, JWKInterface
{
    use Storable;

    /**
     * @var array
     */
    protected $parameters;

    /**
     * StorableJWK constructor.
     *
     * @param string $filename
     * @param array  $parameters
     */
    public function __construct($filename, array $parameters)
    {
        $this->setFilename($filename);
        $this->parameters = $parameters;
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
    protected function getJWK()
    {
        $this->loadObjectIfNeeded();

        return $this->getObject();
    }

    protected function createNewObject()
    {
        $data = JWKFactory::createKey($this->parameters)->getAll();
        $data['kid'] = Base64Url::encode(random_bytes(64));

        return JWKFactory::createFromValues($data);
    }

    /**
     * @param array $file_content
     *
     * @return \JsonSerializable
     */
    protected function createObjectFromFileContent(array $file_content)
    {
        return new JWK($file_content);
    }
}
