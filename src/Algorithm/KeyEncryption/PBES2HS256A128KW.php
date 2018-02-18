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

use AESKW\A128KW as Wrapper;

/**
 * Class PBES2HS256A128KW.
 */
final class PBES2HS256A128KW extends PBES2AESKW
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
    protected function getHashAlgorithm()
    {
        return 'sha256';
    }

    /**
     * {@inheritdoc}
     */
    protected function getKeySize()
    {
        return 16;
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithmName()
    {
        return 'PBES2-HS256+A128KW';
    }
}
