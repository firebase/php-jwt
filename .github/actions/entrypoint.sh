#!/bin/sh -l

apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 7638D0442B90D010 && \
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 9D6D8F6BC857C906 && \
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys AA8E81B4331F7F50 && \
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
php composer.phar update

echo "---Running unit tests ---"
vendor/bin/phpunit
