<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle;

use SpomkyLabs\JoseBundle\DependencyInjection\Compiler\AlgorithmCompilerPass;
use SpomkyLabs\JoseBundle\DependencyInjection\Compiler\CheckerCompilerPass;
use SpomkyLabs\JoseBundle\DependencyInjection\Compiler\CompressionCompilerPass;
use SpomkyLabs\JoseBundle\DependencyInjection\SpomkyLabsJoseBundleExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

final class SpomkyLabsJoseBundle extends Bundle
{
    /**
     * {@inheritdoc}
     */
    public function getContainerExtension()
    {
        return new SpomkyLabsJoseBundleExtension('jose', __DIR__);
    }

    /**
     * {@inheritdoc}
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $container->addCompilerPass(new AlgorithmCompilerPass());
        $container->addCompilerPass(new CompressionCompilerPass());
        $container->addCompilerPass(new CheckerCompilerPass());
    }
}
