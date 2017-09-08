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

use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class RotateCommand extends ContainerAwareCommand
{
    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        $this
            ->setName('keyset:rotate')
            ->setDescription('Rotate a key set.')
            ->addArgument(
                'service',
                InputArgument::REQUIRED
            )
            ->addArgument(
                'ttl',
                InputArgument::OPTIONAL,
                '',
                3600 * 24 * 7
            )
            ->setHelp(<<<'EOT'
The <info>%command.name%</info> command will rotate a key or keys in the key set.

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
        if (!$service instanceof JWKSetInterface) {
            $output->writeln(sprintf('<error>The service "%s" is not a key set.</error>', $service_name));

            return 2;
        }

        if (!$service instanceof RotatableInterface) {
            $output->writeln(sprintf('<error>The service "%s" is not a rotatable key set.</error>', $service_name));

            return 3;
        }

        $mtime = $service->getLastModificationTime();

        if (null === $mtime) {
            $service->regen();
            $output->writeln('Done.');
        } elseif ($mtime + $input->getArgument('ttl') <= time()) {
            $service->rotate();
            $output->writeln('Done.');
        } else {
            $output->writeln(sprintf('The key set "%s" has not expired.', $service_name));
        }
    }
}
