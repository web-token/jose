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

final class RandomOKPKey extends RandomKey
{
    /**
     * {@inheritdoc}
     */
    protected function getKeyConfig(array $config)
    {
        $values = $config['key_configuration'];
        $values['kty'] = 'OKP';
        $values['crv'] = $config['curve'];

        return $values;
    }

    /**
     * {@inheritdoc}
     */
    public function getKey()
    {
        return 'okp';
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
                        ->thenInvalid('Unsupported curve. Please use "X25519" or "Ed25519".')
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
            return !in_array($v, ['X25519', 'Ed25519']);
        };
    }
}
