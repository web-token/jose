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

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Humbug\SelfUpdate\Updater;

final class RollbackCommand extends Command
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
            $result = $updater->rollback();
            if (!$result) {
                echo "Failure!\n";
                exit(1);
            }
            echo "Success!\n";
        } catch (\Exception $e) {
            echo "Well, something happened! Either an oopsie or something involving hackers.\n";
            exit(1);
        }
    }
}
