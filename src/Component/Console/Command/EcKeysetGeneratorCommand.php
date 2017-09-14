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

use Jose\Component\Core\JWKSet;
use Jose\Component\Core\JWKFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class EcKeysetGeneratorCommand extends AbstractGeneratorCommand
{
    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        parent::configure();
        $this
            ->setName('keyset:generate:ec')
            ->setDescription('Generate an EC key set (JWKSet format)')
            ->addArgument('quantity', InputArgument::REQUIRED, 'Quantity of keys in the key set.')
            ->addArgument('curve', InputArgument::REQUIRED, 'Curve of the keys.');
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $quantity = (int) $input->getArgument('quantity');
        $curve = $input->getArgument('curve');
        $args = $this->getOptions($input);

        $keyset = JWKSet::createFromKeys([]);
        for ($i = 0; $i < $quantity; ++$i) {
            $keyset = $keyset->with(JWKFactory::createECKey($curve, $args));
        }
        $this->prepareOutput($input, $output, $keyset);
    }
}
