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

namespace Jose\Bundle\KeyManagement\Command;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\KeyAnalyzer\JWKAnalyzerManager;
use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class KeyAnalyzerCommand extends ContainerAwareCommand
{
    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        $this
            ->setName('key:analyze')
            ->setDescription('JWK quality analyzer.')
            ->setHelp('This command will analyze a JWK object and find security issues.')
            ->addArgument('jwk', InputArgument::REQUIRED, 'The JWK object')
        ;
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        /** @var JWKAnalyzerManager $analyzerManager */
        $analyzerManager = $this->getContainer()->get(JWKAnalyzerManager::class);
        $jwk = $this->getKey($input);

        $result = $analyzerManager->analyze($jwk);
        foreach ($result as $message) {
            $output->writeln($message);
        }
    }

    /**
     * @param InputInterface $input
     *
     * @return JWK
     */
    private function getKey(InputInterface $input): JWK
    {
        $jwkset = $input->getArgument('jwk');
        $json = json_decode($jwkset, true);
        if (is_array($json)) {
            return JWK::create($json);
        } elseif ($this->getContainer()->has($jwkset)) {
            $id = $this->getContainer()->get($jwkset);
            if ($id instanceof JWK) {
                return $id;
            }
        }

        throw new \InvalidArgumentException('The argument must be a valid JWKSet or a service ID to a JWKSet.');
    }
}