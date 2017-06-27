<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle\Features\Context;

/**
 * Behat context trait.
 */
trait VariableContext
{
    /**
     * @Then the variable :variable should be a string with value :value
     */
    public function theVariableShouldBeAStringWithValue($variable, $value)
    {
        if ($value !== $this->$variable) {
            throw new \Exception(sprintf(
                'The value of the variable "%s" is "%s"',
                $variable,
                $this->$variable
            ));
        }
    }

    /**
     * @Then the variable :variable should be a string
     */
    public function theVariableShouldBeAString($variable)
    {
        if (!is_string($this->$variable)) {
            throw new \Exception(sprintf(
                'The variable "%s" is not a string. Its class is "%s"',
                $variable,
                get_class($this->$variable)
            ));
        }
    }

    /**
     * @Then I print the variable :variable
     */
    public function iPrintTheVariable($variable)
    {
        dump($this->$variable);
    }

    /**
     * @Then I unset the variable :variable
     */
    public function iUnsetTheVariable($variable)
    {
        unset($this->$variable);
    }
}
