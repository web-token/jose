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
class StorableJWKSet implements StorableInterface, JWKSetInterface
{
    use Storable;
    use JWKSetPEM;

    /**
     * @var array
     */
    protected $parameters;

    /**
     * @var int
     */
    protected $nb_keys;

    /**
     * StorableJWKSet constructor.
     *
     * @param string $filename
     * @param array  $parameters
     * @param int    $nb_keys
     */
    public function __construct($filename, array $parameters, $nb_keys)
    {
        Assertion::integer($nb_keys, 'The key set must contain at least one key.');
        Assertion::greaterThan($nb_keys, 0, 'The key set must contain at least one key.');
        $this->setFilename($filename);
        $this->parameters = $parameters;
        $this->nb_keys = $nb_keys;
    }

    /**
     * {@inheritdoc}
     */
    public function current()
    {
        return $this->getJWKSet()->current();
    }

    /**
     * {@inheritdoc}
     */
    public function next()
    {
        $this->getJWKSet()->next();
    }

    /**
     * {@inheritdoc}
     */
    public function key()
    {
        return $this->getJWKSet()->key();
    }

    /**
     * {@inheritdoc}
     */
    public function valid()
    {
        return $this->getJWKSet()->valid();
    }

    /**
     * {@inheritdoc}
     */
    public function rewind()
    {
        $this->getJWKSet()->rewind();
    }

    /**
     * {@inheritdoc}
     */
    public function offsetExists($offset)
    {
        return $this->getJWKSet()->offsetExists($offset);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetGet($offset)
    {
        return $this->getJWKSet()->offsetGet($offset);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetSet($offset, $value)
    {
        // Not available
    }

    /**
     * {@inheritdoc}
     */
    public function offsetUnset($offset)
    {
        // Not available
    }

    /**
     * {@inheritdoc}
     */
    public function getKey($index)
    {
        return $this->getJWKSet()->getKey($index);
    }

    /**
     * {@inheritdoc}
     */
    public function hasKey($index)
    {
        return $this->getJWKSet()->hasKey($index);
    }

    /**
     * {@inheritdoc}
     */
    public function getKeys()
    {
        return $this->getJWKSet()->getKeys();
    }

    /**
     * {@inheritdoc}
     */
    public function addKey(JWKInterface $key)
    {
        // Not available
    }

    /**
     * {@inheritdoc}
     */
    public function removeKey($index)
    {
        // Not available
    }

    /**
     * {@inheritdoc}
     */
    public function countKeys()
    {
        return $this->getJWKSet()->countKeys();
    }

    /**
     * {@inheritdoc}
     */
    public function selectKey($type, $algorithm = null, array $restrictions = [])
    {
        return $this->getJWKSet()->selectKey($type, $algorithm, $restrictions);
    }

    /**
     * {@inheritdoc}
     */
    public function count()
    {
        return $this->getJWKSet()->count();
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
    protected function getJWKSet()
    {
        $this->loadObjectIfNeeded();

        return $this->getObject();
    }

    /**
     * @param array $file_content
     *
     * @return \JsonSerializable
     */
    protected function createObjectFromFileContent(array $file_content)
    {
        return new JWKSet($file_content);
    }

    /**
     * This method creates the JWKSet and populate it with keys.
     */
    protected function createNewObject()
    {
        $jwkset = new JWKSet();
        for ($i = 0; $i < $this->nb_keys; $i++) {
            $key = $this->createJWK();
            $jwkset->addKey($key);
        }

        return $jwkset;
    }

    /**
     * @return \Jose\Object\JWKInterface
     */
    protected function createJWK()
    {
        $data = JWKFactory::createKey($this->parameters)->getAll();
        $data['kid'] = Base64Url::encode(random_bytes(64));

        return JWKFactory::createFromValues($data);
    }
}
