[![Build Status](https://travis-ci.org/firebase/php-jwt.png?branch=master)](https://travis-ci.org/firebase/php-jwt)

PHP-JWT
=======
A simple library to encode and decode JSON Web Tokens (JWT) in PHP. Should
conform to the [current spec](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06)

Installation
------------

Use composer to manage your dependencies and download PHP-JWT:

```bash
composer require firebase/php-jwt
```

Example
-------
```php
<?php

$key = "example_key";
$token = array(
    "iss" => "http://example.org",
    "aud" => "http://example.com",
    "iat" => 1356999524,
    "nbf" => 1357000000
);

/**
 * IMPORTANT:
 * You must specify supported algorithms for your application. See
 * https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
 * for a list of spec-compliant algorithms.
 */
$jwt = JWT::encode($token, $key);
$decoded = JWT::decode($jwt, $key, array('HS256'));

print_r($decoded);

/*
 NOTE: This will now be an object instead of an associative array. To get
 an associative array, you will need to cast it as such:
*/

$decoded_array = (array) $decoded;

?>
```

Tests
-----
Run the tests using phpunit:

```bash
$ pear install PHPUnit
$ phpunit --configuration phpunit.xml.dist
PHPUnit 3.7.10 by Sebastian Bergmann.
.....
Time: 0 seconds, Memory: 2.50Mb
OK (5 tests, 5 assertions)
```

License
-------
[3-Clause BSD](http://opensource.org/licenses/BSD-3-Clause).
