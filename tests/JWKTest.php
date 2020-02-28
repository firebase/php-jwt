<?php
namespace Firebase\JWT;

use PHPUnit\Framework\TestCase;

class JWKTest extends TestCase
{
    /*
     * For compatibility with PHPUnit 4.8 and PHP < 5.6
     */
    public function setExpectedException($exceptionName, $message = '', $code = NULL) {
        if (method_exists($this, 'expectException')) {
            $this->expectException($exceptionName);
        } else {
            parent::setExpectedException($exceptionName, $message, $code);
        }
    }

    public function testDecodeByJWKKeySetTokenExpired()
    {
        $jsKey = array(
            'kty' => 'RSA',
            'e'   => 'AQAB',
            'use' => 'sig',
            'kid' => 's1',
            'n'   => 'kWp2zRA23Z3vTL4uoe8kTFptxBVFunIoP4t_8TDYJrOb7D1iZNDXVeEsYKp6ppmrTZDAgd-cNOTKLd4M39WJc5FN0maTAVKJc7NxklDeKc4dMe1BGvTZNG4MpWBo-taKULlYUu0ltYJuLzOjIrTHfarucrGoRWqM0sl3z2-fv9k',
        );

        $key = JWK::parseKeySet(array('keys' => array($jsKey)));

        $header = array(
            'kid' => 's1',
            'alg' => 'RS256',
        );
        $payload = array (
            'scp' => array ('openid', 'email', 'profile', 'aas'),
            'sub' => 'tUCYtnfIBPWcrSJf4yBfvN1kww4KGcy3LIPk1GVzsE0',
            'clm' => array ('!5v8H'),
            'iss' => 'http://130.211.243.114:8080/c2id',
            'exp' => 1441126539,
            'uip' => array('groups' => array('admin', 'audit')),
            'cid' => 'pk-oidc-01',
        );
        $signature = 'PvYrnf3k1Z0wgRwCgq0WXKaoIv1hHtzBFO5cGfCs6bl4suc6ilwCWmJqRxGYkU2fNTGyMOt3OUnnBEwl6v5qN6jv7zbkVAVKVvbQLxhHC2nXe3izvoCiVaMEH6hE7VTWwnPbX_qO72mCwTizHTJTZGLOsyXLYM6ctdOMf7sFPTI';
        $msg = sprintf('%s.%s.%s',
            JWT::urlsafeB64Encode(json_encode($header)),
            JWT::urlsafeB64Encode(json_encode($payload)),
            $signature
        );

        $this->setExpectedException('Firebase\JWT\ExpiredException');

        JWT::decode($msg, $key, array('RS256'));
    }

    public function testDecodeByJWKKeySet()
    {
        $jsKey = array(
            'kty' => 'RSA',
            'e'   => 'AQAB',
            'use' => 'sig',
            'kid' => 's1',
            'n'   => 'kWp2zRA23Z3vTL4uoe8kTFptxBVFunIoP4t_8TDYJrOb7D1iZNDXVeEsYKp6ppmrTZDAgd-cNOTKLd4M39WJc5FN0maTAVKJc7NxklDeKc4dMe1BGvTZNG4MpWBo-taKULlYUu0ltYJuLzOjIrTHfarucrGoRWqM0sl3z2-fv9k',
        );

        $key = JWK::parseKeySet(array('keys' => array($jsKey)));

        $header = array(
            'kid' => 's1',
            'alg' => 'RS256',
        );
        $payload = array (
            'scp' => array ('openid', 'email', 'profile', 'aas'),
            'sub' => 'tUCYtnfIBPWcrSJf4yBfvN1kww4KGcy3LIPk1GVzsE0',
            'clm' => array ('!5v8H'),
            'iss' => 'http://130.211.243.114:8080/c2id',
            'exp' => 1441126539,
            'uip' => array('groups' => array('admin', 'audit')),
            'cid' => 'pk-oidc-01',
        );
        $signature = 'PvYrnf3k1Z0wgRwCgq0WXKaoIv1hHtzBFO5cGfCs6bl4suc6ilwCWmJqRxGYkU2fNTGyMOt3OUnnBEwl6v5qN6jv7zbkVAVKVvbQLxhHC2nXe3izvoCiVaMEH6hE7VTWwnPbX_qO72mCwTizHTJTZGLOsyXLYM6ctdOMf7sFPTI';
        $msg = sprintf('%s.%s.%s',
            JWT::urlsafeB64Encode(json_encode($header)),
            JWT::urlsafeB64Encode(json_encode($payload)),
            $signature
        );

        $this->setExpectedException('Firebase\JWT\ExpiredException');

        $payload = JWT::decode($msg, $key, array('RS256'));

        $this->assertEquals("tUCYtnfIBPWcrSJf4yBfvN1kww4KGcy3LIPk1GVzsE0", $payload->sub);
        $this->assertEquals(1441126539, $payload->exp);
    }

    public function testDecodeByMultiJWKKeySet()
    {
        $jsKey1 = array(
            'kty' => 'RSA',
            'e'   => 'AQAB',
            'use' => 'sig',
            'kid' => 'CXup',
            'n'   => 'hrwD-lc-IwzwidCANmy4qsiZk11yp9kHykOuP0yOnwi36VomYTQVEzZXgh2sDJpGgAutdQudgwLoV8tVSsTG9SQHgJjH9Pd_9V4Ab6PANyZNG6DSeiq1QfiFlEP6Obt0JbRB3W7X2vkxOVaNoWrYskZodxU2V0ogeVL_LkcCGAyNu2jdx3j0DjJatNVk7ystNxb9RfHhJGgpiIkO5S3QiSIVhbBKaJHcZHPF1vq9g0JMGuUCI-OTSVg6XBkTLEGw1C_R73WD_oVEBfdXbXnLukoLHBS11p3OxU7f4rfxA_f_72_UwmWGJnsqS3iahbms3FkvqoL9x_Vj3GhuJSf97Q',
        );
        $jsKey2 = array(
            'kty' => 'EC',
            'use' => 'sig',
            'crv' => 'P-256',
            'kid' => 'yGvt',
            'x'   => 'pvgdqM3RCshljmuCF1D2Ez1w5ei5k7-bpimWLPNeEHI',
            'y'   => 'JSmUhbUTqiFclVLEdw6dz038F7Whw4URobjXbAReDuM',
        );
        $jsKey3 = array(
            'kty' => 'EC',
            'use' => 'sig',
            'crv' => 'P-384',
            'kid' => '9nHY',
            'x'   => 'JPKhjhE0Bj579Mgj3Cn3ERGA8fKVYoGOaV9BPKhtnEobphf8w4GSeigMesL-038W',
            'y'   => 'UbJa1QRX7fo9LxSlh7FOH5ABT5lEtiQeQUcX9BW0bpJFlEVGqwec80tYLdOIl59M',
        );
        $jsKey4 = array(
            'kty' => 'EC',
            'use' => 'sig',
            'crv' => 'P-521',
            'kid' => 'tVzS',
            'x'   => 'AZgkRHlIyNQJlPIwTWdHqouw41k9dS3GJO04BDEnJnd_Dd1owlCn9SMXA-JuXINn4slwbG4wcECbctXb2cvdGtmn',
            'y'   => 'AdBC6N9lpupzfzcIY3JLIuc8y8MnzV-ItmzHQcC5lYWMTbuM9NU_FlvINeVo8g6i4YZms2xFB-B0VVdaoF9kUswC',
        );

        $key = JWK::parseKeySet(array('keys' => array($jsKey1, $jsKey2, $jsKey3, $jsKey4)));

        $header = array(
            'kid' => 'CXup',
            'alg' => 'RS256',
        );
        $payload = array(
            'sub' => 'f8b67cc46030777efd8bce6c1bfe29c6c0f818ec',
            'scp' => array('openid', 'name', 'profile', 'picture', 'email', 'rs-pk-main', 'rs-pk-so', 'rs-pk-issue', 'rs-pk-web'),
            'clm' => array('!5v8H'),
            'iss' => 'https://id.projectkit.net/authenticate',
            'exp' => 1492228336,
            'iat' => 1491364336,
            'cid' => 'cid-pk-web',
        );
        $signature = 'KW1K-72bMtiNwvyYBgffG6VaG6I59cELGYQR8M2q7HA8dmzliu6QREJrqyPtwW_rDJZbsD3eylvkRinK9tlsMXCOfEJbxLdAC9b4LKOsnsbuXXwsJHWkFG0a7osdW0ZpXJDoMFlO1aosxRGMkaqhf1wIkvQ5PM_EB08LJv7oz64Antn5bYaoajwgvJRl7ChatRDn9Sx5UIElKD1BK4Uw5WdrZwBlWdWZVNCSFhy4F6SdZvi3OBlXzluDwq61RC-pl2iivilJNljYWVrthHDS1xdtaVz4oteHW13-IS7NNEz6PVnzo5nyoPWMAB4JlRnxcfOFTTUqOA2mX5Csg0UpdQ';
        $msg = sprintf('%s.%s.%s',
            JWT::urlsafeB64Encode(json_encode($header)),
            JWT::urlsafeB64Encode(json_encode($payload)),
            $signature
        );

        $this->setExpectedException('Firebase\JWT\ExpiredException');

        $payload = JWT::decode($msg, $key, array('RS256'));

        $this->assertEquals("f8b67cc46030777efd8bce6c1bfe29c6c0f818ec", $payload->sub);
        $this->assertEquals(1492228336, $payload->exp);
    }
}
