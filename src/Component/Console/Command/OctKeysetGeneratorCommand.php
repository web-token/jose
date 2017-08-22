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
use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputDefinition;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class OctKeysetGeneratorCommand extends Command
{
    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        $this
            ->setName('keyset:generate:oct')
            ->setDescription('Generate a key set with octet keys (JWK format)')
            ->setDefinition(
                new InputDefinition([
                    new InputOption('quantity', null, InputOption::VALUE_REQUIRED, 'Quantity of keys in the key set.'),
                    new InputOption('size', 's', InputOption::VALUE_OPTIONAL, 'Key size.', 2048),
                    new InputOption('use', 'u', InputOption::VALUE_OPTIONAL, 'Usage of the key. Must be either "sig" or "enc".'),
                    new InputOption('alg', 'a', InputOption::VALUE_OPTIONAL, 'Algorithm for the key.'),
                    new InputOption('out', 'o', InputOption::VALUE_OPTIONAL, 'File where to save the key. Must be a valid and writable file name.'),
                ])
            )
        ;
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $quantity = (int) $input->getOption('quantity');
        $size = (int) $input->getOption('size');
        $args = [];
        foreach (['use', 'alg'] as $key) {
            $value = $input->getOption($key);
            if (null !== $value) {
                $args[$key] = $value;
            }
        }

        $keyset = JWKSet::createFromKeys([]);
        for ($i = 0; $i < $quantity; ++$i) {
            $keyset = $keyset->withKey(JWKFactory::createOctKey($size, $args));
        }
        $json = json_encode($keyset);

        $file = $input->getOption('out');
        if (null !== $file) {
            file_put_contents($file, $json, LOCK_EX);
        } else {
            $output->write($json);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled()
    {
        return class_exists('\Jose\Component\KeyManagement\JWKFactory');
    }
}
