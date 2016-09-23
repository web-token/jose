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
class StorableJWKSet implements StorableJWKSetInterface
{
    /**
     * @var \Jose\Object\JWKSetInterface
     */
    protected $jwkset;

    /**
     * @var string
     */
    protected $filename;

    /**
     * @var array
     */
    protected $parameters;

    /**
     * @var int
     */
    protected $nb_keys;

    /**
     * @var null|int
     */
    protected $file_last_modification_time = null;

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
        return $this->getJWKSet()->offsetSet($offset, $value);
    }

    /**
     * {@inheritdoc}
     */
    public function offsetUnset($offset)
    {
        return $this->getJWKSet()->offsetUnset($offset);
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
        return $this->getJWKSet()->addKey($key);
    }

    /**
     * {@inheritdoc}
     */
    public function removeKey($index)
    {
        return $this->getJWKSet()->removeKey($index);
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
     * @return string
     */
    protected function getFilename()
    {
        return $this->filename;
    }

    /**
     * @return \Jose\Object\JWKSetInterface
     */
    protected function getJWKSet()
    {
        $this->loadJWKSetIfNeeded();

        return $this->jwkset;
    }

    /**
     * This function loads or creates it the file if needed.
     */
    protected function loadJWKSetIfNeeded()
    {
        if (false === $this->hasFileBeenUpdated()) {
            return;
        }
        $content = $this->getFileContent();
        if (null === $content) {
            $this->createJWKSet();
        } else {
            $this->jwkset = new JWKSet($content);
            $this->file_last_modification_time = $this->getFileLastModificationTime();
        }
    }

    /**
     * @return bool
     */
    protected function hasFileBeenUpdated()
    {
        if (null === $this->file_last_modification_time || null === $this->getFileLastModificationTime()) {
            return true;
        }

        return $this->file_last_modification_time !== $this->getFileLastModificationTime();
    }

    protected function getFileLastModificationTime()
    {
        if (file_exists($this->getFilename())) {
            return filemtime($this->getFilename());
        }
    }

    /**
     * This function returns the content of the file only if it is an array.
     *
     * @return null|array
     */
    protected function getFileContent()
    {
        if (!file_exists($this->getFilename())) {
            return;
        }
        $content = file_get_contents($this->getFilename());
        if (false === $content) {
            return;
        }
        $content = json_decode($content, true);
        if (!is_array($content)) {
            return;
        }

        return $content;
    }

    /**
     * This method creates the JWKSet and populate it with keys.
     */
    protected function createJWKSet()
    {
        $this->jwkset = new JWKSet();
        for ($i = 0; $i < $this->nb_keys; $i++) {
            $key = $this->createJWK();
            $this->jwkset->addKey($key);
        }

        $this->save();
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

    /**
     * This method saves the JWKSet in the file.
     */
    protected function save()
    {
        if (file_exists($this->getFilename())) {
            unlink($this->getFilename());
        }
        file_put_contents($this->getFilename(), json_encode($this->jwkset));
        $this->file_last_modification_time = $this->getFileLastModificationTime();
    }
}
