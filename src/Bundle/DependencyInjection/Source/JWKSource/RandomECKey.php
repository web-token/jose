<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle\DependencyInjection\Source\JWKSource;

use Symfony\Component\Config\Definition\Builder\NodeDefinition;

final class RandomECKey extends RandomKey
{
    /**
     * {@inheritdoc}
     */
    protected function getKeyConfig(array $config)
    {
        $values = $config['key_configuration'];
        $values['kty'] = 'EC';
        $values['crv'] = $config['curve'];

        return $values;
    }

    /**
     * {@inheritdoc}
     */
    public function getKey()
    {
        return 'ec';
    }

    /**
     * {@inheritdoc}
     */
    public function addConfiguration(NodeDefinition $node)
    {
        $node
            ->children()
                ->scalarNode('curve')
                    ->validate()
                        ->ifTrue(self::checkCurve())
                        ->thenInvalid('Unsupported curve. Please use "P-256", "P-384" or "P-521".')
                    ->end()
                    ->isRequired()
                ->end()
            ->end();
        parent::addConfiguration($node);
    }

    /**
     * @return \Closure
     */
    private static function checkCurve()
    {
        return function ($v) {
            return !in_array($v, ['P-256', 'P-384', 'P-521']);
        };
    }
}
