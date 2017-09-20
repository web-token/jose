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

/**
 * Class UpdateCommand.
 */
final class UpdateCommand extends Command
{
    protected function configure()
    {
        $this
            ->setName('selfupdate')
            ->setDescription('Update the application if needed.')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $updater = new Updater();
        $updater->setStrategy(Updater::STRATEGY_GITHUB);
        $updater->getStrategy()->setPackageName('spomky-labs/jose');
        $updater->getStrategy()->setPharName('jose');
        $updater->getStrategy()->setCurrentLocalVersion('7.0.0');

        try {
            $result = $updater->update();
            if ($result) {
                $new = $updater->getNewVersion();
                $old = $updater->getOldVersion();
                $output->write(sprintf('Updated from SHA-1 %s to SHA-1 %s', $old, $new));
            } else {
                $output->write('No update needed!');
            }
        } catch (\Exception $e) {
            $output->write('Well, something happened! Either an oopsie or something involving hackers.');
        }
    }
}
