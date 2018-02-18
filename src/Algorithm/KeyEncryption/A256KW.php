<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\KeyEncryption;

use AESKW\A256KW as Wrapper;

/**
 * Class A256KW.
 */
final class A256KW extends AESKW
{
    /**
     * {@inheritdoc}
     */
    protected function getWrapper()
    {
        return new Wrapper();
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithmName()
    {
        return 'A256KW';
    }

    /**
     * {@inheritdoc}
     */
    protected function getKeySize()
    {
        return 32;
    }
}
