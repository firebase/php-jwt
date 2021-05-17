#!/bin/sh -l

curl --silent --show-error https://getcomposer.org/installer | php
php composer.phar self-update

echo "---Installing dependencies ---"
php composer.phar update

echo "---Running unit tests ---"
vendor/bin/phpunit
