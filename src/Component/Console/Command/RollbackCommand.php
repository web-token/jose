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

use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Humbug\SelfUpdate\Updater;

final class RollbackCommand extends AbstractGeneratorCommand
{
    protected function configure()
    {
        $this
            ->setName('rollback')
            ->setDescription('Rollback current version.')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $updater = new Updater();

        try {
            if (!$updater->rollback()) {
                $output->write('Failure!');
            } else {
                $output->write('Success!');
            }
        } catch (\Exception $e) {
            $output->write('Well, something happened! Either an oopsie or something involving hackers.');
        }
    }
}
