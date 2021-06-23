#!/bin/sh -l

apt-get update && \
apt-get install -y --no-install-recommends \
    git \
    zip \
    curl \
    unzip \
    wget

curl --silent --show-error https://getcomposer.org/installer | php
php composer.phar self-update

echo "---Installing dependencies ---"

echo "---Add compatiblity for libsodium with older versions of PHP ---"
composer require --dev --with-dependencies paragonie/sodium_compat

echo "---Running unit tests ---"
vendor/bin/phpunit
