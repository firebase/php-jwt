
PHP-JWT
=======
A simple library to encode and decode JSON Web Tokens (JWT) in PHP. Should
conform to the [current spec](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06)

Example
-------
```php
<?php
  include_once 'JWT.php';

  $key = "example_key";
  $token = array(
    "iss" => "http://example.org",
    "aud" => "http://example.com",
    "iat" => 1356999524,
    "nbf" => 1357000000
  );

  $jwt = JWT::encode($token, $key);
  $decoded = JWT::decode($jwt, $key);

  print_r($decoded);
?>
```

License
-------
[3-Clause BSD](http://opensource.org/licenses/BSD-3-Clause).
