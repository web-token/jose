#!/usr/bin/env bash

git clone git://github.com/lt/php-curve25519-ext.git
cd php-curve25519-ext
phpize
./configure
make
sudo make install
cd ..
rm -rf php-curve25519-ext
echo "extension = curve25519.so" >> ~/.phpenv/versions/$(phpenv version-name)/etc/php.ini
git clone git://github.com/encedo/php-ed25519-ext.git
cd php-ed25519-ext
phpize
./configure
make
sudo make install
cd ..
rm -rf php-ed25519-ext
echo "extension = ed25519.so" >> ~/.phpenv/versions/$(phpenv version-name)/etc/php.ini
