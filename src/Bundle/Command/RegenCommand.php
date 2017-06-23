<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\JoseBundle\Command;

use Jose\Object\StorableInterface;
use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class RegenCommand extends ContainerAwareCommand
{
    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        $this
            ->setName('spomky-labs:jose:regen')
            ->setDescription('Generate a new key or key set.')
            ->addArgument(
                'service',
                InputArgument::REQUIRED
            )
            ->setHelp(<<<'EOT'
The <info>%command.name%</info> command will generate a new key or key set.

  <info>php %command.full_name%</info>
EOT
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $service_name = $input->getArgument('service');
        if (!$this->getContainer()->has($service_name)) {
            $output->writeln(sprintf('<error>The service "%s" does not exist.</error>', $service_name));

            return 1;
        }
        $service = $this->getContainer()->get($service_name);
        if (!$service instanceof StorableInterface) {
            $output->writeln(sprintf('<error>The service "%s" is not a storable object.</error>', $service_name));

            return 2;
        }

        $service->regen();
        $output->writeln('Done.');
    }
}
