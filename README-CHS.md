[![Build Status](https://travis-ci.org/firebase/php-jwt.png?branch=master)](https://travis-ci.org/firebase/php-jwt)
[![Latest Stable Version](https://poser.pugx.org/firebase/php-jwt/v/stable)](https://packagist.org/packages/firebase/php-jwt)
[![Total Downloads](https://poser.pugx.org/firebase/php-jwt/downloads)](https://packagist.org/packages/firebase/php-jwt)
[![License](https://poser.pugx.org/firebase/php-jwt/license)](https://packagist.org/packages/firebase/php-jwt)

PHP-JWT
=======
一个简单的库，用于 PHP 中编解码 JSON Web Tokens（JWT），符合 [RFC 7519](https://tools.ietf.org/html/rfc7519)。

安装
------------

使用 composer 来管理您的依赖项并下载 PHP-JWT：

```bash
composer require firebase/php-jwt
```

例子
-------
```php
<?php
use \Firebase\JWT\JWT;

$key = "example_key";
$token = array(
    "iss" => "http://example.org",
    "aud" => "http://example.com",
    "iat" => 1356999524,
    "nbf" => 1357000000
);

/**
 * 重要:
 * 您必须为您的应用程序指定一个支持的算法。参考
 * https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
 * 以了解符合规范的算法列表。
 */
$jwt = JWT::encode($token, $key);
$decoded = JWT::decode($jwt, $key, array('HS256'));

print_r($decoded);

/*
 注意：这是一个对象而不是数组。为得到到一个关联数组，您需要将其像这样转换：
*/

$decoded_array = (array) $decoded;

/**
 * 当签名服务器和验证服务器之间存在偏移时，您可以添加 leeway。建议这个值不超过几分钟。
 *
 * 来源：http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#nbfDef
 */
JWT::$leeway = 60; // $leeway in seconds
$decoded = JWT::decode($jwt, $key, array('HS256'));

?>
```
RS256 例子 (openssl)
----------------------------
```php
<?php
use \Firebase\JWT\JWT;

$privateKey = <<<EOD
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC8kGa1pSjbSYZVebtTRBLxBz5H4i2p/llLCrEeQhta5kaQu/Rn
vuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t0tyazyZ8JXw+KgXTxldMPEL9
5+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4ehde/zUxo6UvS7UrBQIDAQAB
AoGAb/MXV46XxCFRxNuB8LyAtmLDgi/xRnTAlMHjSACddwkyKem8//8eZtw9fzxz
bWZ/1/doQOuHBGYZU8aDzzj59FZ78dyzNFoF91hbvZKkg+6wGyd/LrGVEB+Xre0J
Nil0GReM2AHDNZUYRv+HYJPIOrB0CRczLQsgFJ8K6aAD6F0CQQDzbpjYdx10qgK1
cP59UHiHjPZYC0loEsk7s+hUmT3QHerAQJMZWC11Qrn2N+ybwwNblDKv+s5qgMQ5
5tNoQ9IfAkEAxkyffU6ythpg/H0Ixe1I2rd0GbF05biIzO/i77Det3n4YsJVlDck
ZkcvY3SK2iRIL4c9yY6hlIhs+K9wXTtGWwJBAO9Dskl48mO7woPR9uD22jDpNSwe
k90OMepTjzSvlhjbfuPN1IdhqvSJTDychRwn1kIJ7LQZgQ8fVz9OCFZ/6qMCQGOb
qaGwHmUK6xzpUbbacnYrIM6nLSkXgOAwv7XXCojvY614ILTK3iXiLBOxPu5Eu13k
eUz9sHyD6vkgZzjtxXECQAkp4Xerf5TGfQXGXhxIX52yH+N2LtujCdkQZjXAsGdm
B2zNzvrlgRmgBrklMTrMYgm1NPcW+bRLGcwgW2PTvNM=
-----END RSA PRIVATE KEY-----
EOD;

$publicKey = <<<EOD
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kGa1pSjbSYZVebtTRBLxBz5H
4i2p/llLCrEeQhta5kaQu/RnvuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t
0tyazyZ8JXw+KgXTxldMPEL95+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4
ehde/zUxo6UvS7UrBQIDAQAB
-----END PUBLIC KEY-----
EOD;

$token = array(
    "iss" => "example.org",
    "aud" => "example.com",
    "iat" => 1356999524,
    "nbf" => 1357000000
);

$jwt = JWT::encode($token, $privateKey, 'RS256');
echo "Encode:\n" . print_r($jwt, true) . "\n";

$decoded = JWT::decode($jwt, $publicKey, array('RS256'));

/*
 注意：这是一个对象而不是数组，为得到一个关联数组，您需要将其像这样转换：
*/

$decoded_array = (array) $decoded;
echo "Decode:\n" . print_r($decoded_array, true) . "\n";
?>
```

更新日志
---------

#### 5.0.0 / 2017-06-26
- Support RS384 and RS512.
  See [#117](https://github.com/firebase/php-jwt/pull/117). Thanks [@joostfaassen](https://github.com/joostfaassen)!
- Add an example for RS256 openssl.
  See [#125](https://github.com/firebase/php-jwt/pull/125). Thanks [@akeeman](https://github.com/akeeman)!
- Detect invalid Base64 encoding in signature.
  See [#162](https://github.com/firebase/php-jwt/pull/162). Thanks [@psignoret](https://github.com/psignoret)!
- Update `JWT::verify` to handle OpenSSL errors.
  See [#159](https://github.com/firebase/php-jwt/pull/159). Thanks [@bshaffer](https://github.com/bshaffer)!
- Add `array` type hinting to `decode` method
  See [#101](https://github.com/firebase/php-jwt/pull/101). Thanks [@hywak](https://github.com/hywak)!
- Add all JSON error types.
  See [#110](https://github.com/firebase/php-jwt/pull/110). Thanks [@gbalduzzi](https://github.com/gbalduzzi)!
- Bugfix 'kid' not in given key list.
  See [#129](https://github.com/firebase/php-jwt/pull/129). Thanks [@stampycode](https://github.com/stampycode)!
- Miscellaneous cleanup, documentation and test fixes.
  See [#107](https://github.com/firebase/php-jwt/pull/107), [#115](https://github.com/firebase/php-jwt/pull/115),
  [#160](https://github.com/firebase/php-jwt/pull/160), [#161](https://github.com/firebase/php-jwt/pull/161), and
  [#165](https://github.com/firebase/php-jwt/pull/165). Thanks [@akeeman](https://github.com/akeeman),
  [@chinedufn](https://github.com/chinedufn), and [@bshaffer](https://github.com/bshaffer)!

#### 4.0.0 / 2016-07-17
- Add support for late static binding. See [#88](https://github.com/firebase/php-jwt/pull/88) for details. Thanks to [@chappy84](https://github.com/chappy84)!
- Use static `$timestamp` instead of `time()` to improve unit testing. See [#93](https://github.com/firebase/php-jwt/pull/93) for details. Thanks to [@josephmcdermott](https://github.com/josephmcdermott)!
- Fixes to exceptions classes. See [#81](https://github.com/firebase/php-jwt/pull/81) for details. Thanks to [@Maks3w](https://github.com/Maks3w)!
- Fixes to PHPDoc. See [#76](https://github.com/firebase/php-jwt/pull/76) for details. Thanks to [@akeeman](https://github.com/akeeman)!

#### 3.0.0 / 2015-07-22
- Minimum PHP version updated from `5.2.0` to `5.3.0`.
- Add `\Firebase\JWT` namespace. See
[#59](https://github.com/firebase/php-jwt/pull/59) for details. Thanks to
[@Dashron](https://github.com/Dashron)!
- Require a non-empty key to decode and verify a JWT. See
[#60](https://github.com/firebase/php-jwt/pull/60) for details. Thanks to
[@sjones608](https://github.com/sjones608)!
- Cleaner documentation blocks in the code. See
[#62](https://github.com/firebase/php-jwt/pull/62) for details. Thanks to
[@johanderuijter](https://github.com/johanderuijter)!

#### 2.2.0 / 2015-06-22
- Add support for adding custom, optional JWT headers to `JWT::encode()`. See
[#53](https://github.com/firebase/php-jwt/pull/53/files) for details. Thanks to
[@mcocaro](https://github.com/mcocaro)!

#### 2.1.0 / 2015-05-20
- Add support for adding a leeway to `JWT:decode()` that accounts for clock skew
between signing and verifying entities. Thanks to [@lcabral](https://github.com/lcabral)!
- Add support for passing an object implementing the `ArrayAccess` interface for
`$keys` argument in `JWT::decode()`. Thanks to [@aztech-dev](https://github.com/aztech-dev)!

#### 2.0.0 / 2015-04-01
- **Note**: It is strongly recommended that you update to > v2.0.0 to address
  known security vulnerabilities in prior versions when both symmetric and
  asymmetric keys are used together.
- Update signature for `JWT::decode(...)` to require an array of supported
  algorithms to use when verifying token signatures.


测试
-----
使用 phpunit 运行测试：

```bash
$ pear install PHPUnit
$ phpunit --configuration phpunit.xml.dist
PHPUnit 3.7.10 by Sebastian Bergmann.
.....
Time: 0 seconds, Memory: 2.50Mb
OK (5 tests, 5 assertions)
```

私钥换行
-----

如果您的私钥包含 `\n` 换行符, 请务必将其用双引号`""` 包裹，而不是单引号 `''`，以正确解析转移字符

许可
-------
[3-Clause BSD](http://opensource.org/licenses/BSD-3-Clause).
