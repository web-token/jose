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
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class OctKeyGeneratorCommand extends AbstractGeneratorCommand
{
    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        $this
            ->setName('key:generate:oct')
            ->setDescription('Generate a octet key (JWK format)')
            ->addArgument('size', InputArgument::REQUIRED, 'Key size.');
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $size = (int) $input->getArgument('size');
        $args = $this->getOptions($input);

        $jwk = JWKFactory::createOctKey($size, $args);
        $json = json_encode($jwk);
        $this->prepareOutput($input, $output, $json);
    }
}
