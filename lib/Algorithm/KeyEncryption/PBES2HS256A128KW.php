<?php

namespace SpomkyLabs\Jose\Algorithm\KeyEncryption;

use AESKW\A128KW as Wrapper;

class PBES2HS256A128KW extends PBES2AESKW
{
    protected function getWrapper()
    {
        return new Wrapper();
    }

    protected function getHashAlgorithm()
    {
        return "sha256";
    }

    protected function getKeySize()
    {
        return 128/8;
    }

    public function getAlgorithmName()
    {
        return "PBES2-HS256+A128KW";
    }
}