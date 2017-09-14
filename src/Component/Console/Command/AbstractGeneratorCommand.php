<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Console\Command;

use Jose\Component\Core\JWKFactory;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

abstract class AbstractGeneratorCommand extends AbstractObjectOutputCommand
{
    /**
     * {@inheritdoc}
     */
    public function isEnabled()
    {
        return class_exists(JWKFactory::class);
    }

    /**
     * Configures the current command.
     */
    protected function configure()
    {
        parent::configure();
        $this
            ->addOption('use', 'u', InputOption::VALUE_OPTIONAL, 'Usage of the key. Must be either "sig" or "enc".')
            ->addOption('alg', 'a', InputOption::VALUE_OPTIONAL, 'Algorithm for the key.')
        ;
    }

    /**
     * @param InputInterface $input
     *
     * @return array
     */
    protected function getOptions(InputInterface $input): array
    {
        $args = [];
        foreach (['use', 'alg'] as $key) {
            $value = $input->getOption($key);
            if (null !== $value) {
                $args[$key] = $value;
            }
        }

        return $args;
    }
}
