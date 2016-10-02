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

trait Storable
{
    /**
     * @var \JsonSerializable
     */
    protected $object;

    /**
     * @var string
     */
    protected $filename;

    /**
     * @var int|null
     */
    protected $file_modification_time = null;

    /**
     * @param string $filename
     */
    public function setFilename($filename)
    {
        Assertion::string($filename, 'Invalid filename.');
        Assertion::directory(dirname($filename), 'The selected directory does not exist.');
        Assertion::writeable(dirname($filename), 'The selected directory is not writable.');
        $this->filename = $filename;
    }

    /**
     * {@inheritdoc}
     */
    public function regen()
    {
        $this->delete();
        $this->loadObjectIfNeeded();
    }

    /**
     * {@inheritdoc}
     */
    public function delete()
    {
        if (file_exists($this->getFilename())) {
            unlink($this->getFilename());
        }
    }

    /**
     * @return string
     */
    protected function getFilename()
    {
        return $this->filename;
    }

    /**
     * @return \JsonSerializable
     */
    protected function getObject()
    {
        return $this->object;
    }

    /**
     * @param \JsonSerializable $object
     */
    protected function setObject(\JsonSerializable $object)
    {
        $this->object = $object;
    }

    protected function loadObjectIfNeeded()
    {
        if (null !== $this->getObject() && false === $this->hasFileBeenUpdated()) {
            return;
        }

        if (null === $content = $this->getFileContent()) {
            $this->createAndSaveObject();
        } else {
            $this->setObject($this->createObjectFromFileContent($content));
            $this->file_modification_time = filemtime($this->getFilename());
        }
    }

    /**
     * @return array|null
     */
    protected function getFileContent()
    {
        if (file_exists($this->getFilename())) {
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
    }

    /**
     * @return \JsonSerializable
     */
    abstract protected function createNewObject();

    /**
     * @param array $file_content
     *
     * @return \JsonSerializable
     */
    abstract protected function createObjectFromFileContent(array $file_content);

    /**
     * @return int|null
     */
    public function getLastModificationTime()
    {
        if (file_exists($this->getFilename())) {
            return filemtime($this->getFilename());
        }
    }

    /**
     * @return bool
     */
    protected function hasFileBeenUpdated()
    {
        if (null === $this->file_modification_time || null === $this->getLastModificationTime()) {
            return true;
        }

        return $this->file_modification_time !== $this->getLastModificationTime();
    }

    protected function createAndSaveObject()
    {
        $object = $this->createNewObject();
        $this->setObject($object);
        $this->saveObject($object);
    }

    protected function saveObject(\JsonSerializable $object)
    {
        file_put_contents($this->getFilename(), json_encode($object));
        $this->file_modification_time = filemtime($this->getFilename());
    }
}
