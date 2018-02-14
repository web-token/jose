<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Algorithm\ContentEncryption;

/**
 * Class A128GCM.
 */
final class A128GCM extends AESGCM
{
    /**
     * {@inheritdoc}
     */
    protected function getKeySize()
    {
        return 128;
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithmName()
    {
        return 'A128GCM';
    }
}
