<?php
namespace Firebase\JWT;

use ArrayObject;
use PHPUnit_Framework_TestCase;

class JWTTest extends PHPUnit_Framework_TestCase
{
    public static $opensslVerifyReturnValue;

    public function testEncodeDecode()
    {
        $jwt = new JWT();
        $msg = $jwt->encode('abc', 'my_key');
        $this->assertEquals($jwt->decode($msg, 'my_key', array('HS256')), 'abc');
    }

    public function testDecodeFromPython()
    {
        $msg = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.Iio6aHR0cDovL2FwcGxpY2F0aW9uL2NsaWNreT9ibGFoPTEuMjMmZi5vbz00NTYgQUMwMDAgMTIzIg.E_U8X2YpMT5K1cEiT_3-IvBYfrdIFIeVYeOqre_Z5Cg';
        $jwt = new JWT();
        $this->assertEquals(
            $jwt->decode($msg, 'my_key', array('HS256')),
            '*:http://application/clicky?blah=1.23&f.oo=456 AC000 123'
        );
    }

    public function testUrlSafeCharacters()
    {
        $jwt = new JWT();
        $encoded = $jwt->encode('f?', 'a');
        $this->assertEquals('f?', $jwt->decode($encoded, 'a', array('HS256')));
    }

    public function testMalformedUtf8StringsFail()
    {
        $this->setExpectedException('DomainException');
        $jwt = new JWT();
        $jwt->encode(pack('c', 128), 'a');
    }

    public function testMalformedJsonThrowsException()
    {
        $this->setExpectedException('DomainException');
        $jwt = new JWT();
        $jwt->jsonDecode('this is not valid JSON string');
    }

    public function testExpiredToken()
    {
        $this->setExpectedException('Firebase\JWT\ExpiredException');
        $payload = array(
            "message" => "abc",
            "exp" => time() - 20); // time in the past
        $jwt = new JWT();
        $encoded = $jwt->encode($payload, 'my_key');
        $jwt->decode($encoded, 'my_key', array('HS256'));
    }

    public function testBeforeValidTokenWithNbf()
    {
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        $payload = array(
            "message" => "abc",
            "nbf" => time() + 20); // time in the future
        $jwt = new JWT();
        $encoded = $jwt->encode($payload, 'my_key');
        $jwt->decode($encoded, 'my_key', array('HS256'));
    }

    public function testBeforeValidTokenWithIat()
    {
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        $payload = array(
            "message" => "abc",
            "iat" => time() + 20); // time in the future
        $jwt = new JWT();
        $encoded = $jwt->encode($payload, 'my_key');
        $jwt->decode($encoded, 'my_key', array('HS256'));
    }

    public function testValidToken()
    {
        $jwt = new JWT();
        $payload = array(
            "message" => "abc",
            "exp" => time() + $jwt->leeway + 20); // time in the future
        $encoded = $jwt->encode($payload, 'my_key');
        $decoded = $jwt->decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithLeeway()
    {
        $jwt = new JWT();
        $jwt->leeway = 60;
        $payload = array(
            "message" => "abc",
            "exp" => time() - 20); // time in the past
        $encoded = $jwt->encode($payload, 'my_key');
        $decoded = $jwt->decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testExpiredTokenWithLeeway()
    {
        $jwt = new JWT();
        $jwt->leeway = 60;
        $payload = array(
            "message" => "abc",
            "exp" => time() - 70); // time far in the past
        $this->setExpectedException('Firebase\JWT\ExpiredException');
        $encoded = $jwt->encode($payload, 'my_key');
        $decoded = $jwt->decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithList()
    {
        $jwt = new JWT();
        $payload = array(
            "message" => "abc",
            "exp" => time() + 20); // time in the future
        $encoded = $jwt->encode($payload, 'my_key');
        $decoded = $jwt->decode($encoded, 'my_key', array('HS256', 'HS512'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithNbf()
    {
        $jwt = new JWT();
        $payload = array(
            "message" => "abc",
            "iat" => time(),
            "exp" => time() + 20, // time in the future
            "nbf" => time() - 20);
        $encoded = $jwt->encode($payload, 'my_key');
        $decoded = $jwt->decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithNbfLeeway()
    {
        $jwt = new JWT();
        $jwt->leeway = 60;
        $payload = array(
            "message" => "abc",
            "nbf"     => time() + 20); // not before in near (leeway) future
        $encoded = $jwt->encode($payload, 'my_key');
        $decoded = $jwt->decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testInvalidTokenWithNbfLeeway()
    {
        $jwt = new JWT();
        $jwt->leeway = 60;
        $payload = array(
            "message" => "abc",
            "nbf"     => time() + 65); // not before too far in future
        $encoded = $jwt->encode($payload, 'my_key');
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        $decoded = $jwt->decode($encoded, 'my_key', array('HS256'));
    }

    public function testValidTokenWithIatLeeway()
    {
        $jwt = new JWT();
        $jwt->leeway = 60;

        $payload = array(
            "message" => "abc",
            "iat"     => time() + 20); // issued in near (leeway) future
        $encoded = $jwt->encode($payload, 'my_key');
        $decoded = $jwt->decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testInvalidTokenWithIatLeeway()
    {
        $jwt = new JWT();
        $jwt->leeway = 60;

        $payload = array(
            "message" => "abc",
            "iat"     => time() + 65); // issued too far in future
        $encoded = $jwt->encode($payload, 'my_key');
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        $decoded = $jwt->decode($encoded, 'my_key', array('HS256'));
    }

    public function testInvalidToken()
    {
        $jwt = new JWT();
        $payload = array(
            "message" => "abc",
            "exp" => time() + 20); // time in the future
        $encoded = $jwt->encode($payload, 'my_key');
        $this->setExpectedException('Firebase\JWT\SignatureInvalidException');
        $decoded = $jwt->decode($encoded, 'my_key2', array('HS256'));
    }

    public function testNullKeyFails()
    {
        $jwt = new JWT();
        $payload = array(
            "message" => "abc",
            "exp" => time() + $jwt->leeway + 20); // time in the future
        $encoded = $jwt->encode($payload, 'my_key');
        $this->setExpectedException('InvalidArgumentException');
        $decoded = $jwt->decode($encoded, null, array('HS256'));
    }

    public function testEmptyKeyFails()
    {
        $jwt = new JWT();
        $payload = array(
            "message" => "abc",
            "exp" => time() + $jwt->leeway + 20); // time in the future
        $encoded = $jwt->encode($payload, 'my_key');
        $this->setExpectedException('InvalidArgumentException');
        $decoded = $jwt->decode($encoded, '', array('HS256'));
    }

    public function testRSEncodeDecode()
    {
        $jwt = new JWT();
        $privKey = openssl_pkey_new(array('digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA));
        $msg = $jwt->encode('abc', $privKey, 'RS256');
        $pubKey = openssl_pkey_get_details($privKey);
        $pubKey = $pubKey['key'];
        $decoded = $jwt->decode($msg, $pubKey, array('RS256'));
        $this->assertEquals($decoded, 'abc');
    }

    public function testKIDChooser()
    {
        $jwt = new JWT();
        $keys = array('1' => 'my_key', '2' => 'my_key2');
        $msg = $jwt->encode('abc', $keys['1'], 'HS256', '1');
        $decoded = $jwt->decode($msg, $keys, array('HS256'));
        $this->assertEquals($decoded, 'abc');
    }

    public function testArrayAccessKIDChooser()
    {
        $jwt = new JWT();
        $keys = new ArrayObject(array('1' => 'my_key', '2' => 'my_key2'));
        $msg = $jwt->encode('abc', $keys['1'], 'HS256', '1');
        $decoded = $jwt->decode($msg, $keys, array('HS256'));
        $this->assertEquals($decoded, 'abc');
    }

    public function testNoneAlgorithm()
    {
        $jwt = new JWT();
        $msg = $jwt->encode('abc', 'my_key');
        $this->setExpectedException('UnexpectedValueException');
        $jwt->decode($msg, 'my_key', array('none'));
    }

    public function testIncorrectAlgorithm()
    {
        $jwt = new JWT();
        $msg = $jwt->encode('abc', 'my_key');
        $this->setExpectedException('UnexpectedValueException');
        $jwt->decode($msg, 'my_key', array('RS256'));
    }

    public function testMissingAlgorithm()
    {
        $jwt = new JWT();
        $msg = $jwt->encode('abc', 'my_key');
        $this->setExpectedException('UnexpectedValueException');
        $jwt->decode($msg, 'my_key');
    }

    public function testAdditionalHeaders()
    {
        $jwt = new JWT();
        $msg = $jwt->encode('abc', 'my_key', 'HS256', null, array('cty' => 'test-eit;v=1'));
        $this->assertEquals($jwt->decode($msg, 'my_key', array('HS256')), 'abc');
    }

    public function testInvalidSegmentCount()
    {
        $jwt = new JWT();
        $this->setExpectedException('UnexpectedValueException');
        $jwt->decode('brokenheader.brokenbody', 'my_key', array('HS256'));
    }

    public function testInvalidSignatureEncoding()
    {
        $jwt = new JWT();
        $msg = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwibmFtZSI6ImZvbyJ9.Q4Kee9E8o0Xfo4ADXvYA8t7dN_X_bU9K5w6tXuiSjlUxx";
        $this->setExpectedException('UnexpectedValueException');
        $jwt->decode($msg, 'secret', array('HS256'));
    }

    public function testVerifyError()
    {
        $jwt = new JWT();
        $this->setExpectedException('DomainException');
        $pkey = openssl_pkey_new();
        $msg = $jwt->encode('abc', $pkey, 'RS256');
        self::$opensslVerifyReturnValue = -1;
        $jwt->decode($msg, $pkey, array('RS256'));
    }
}

/*
 * Allows the testing of openssl_verify with an error return value
 */
function openssl_verify($msg, $signature, $key, $algorithm)
{
    if (null !== JWTTest::$opensslVerifyReturnValue) {
        return JWTTest::$opensslVerifyReturnValue;
    }
    return \openssl_verify($msg, $signature, $key, $algorithm);
}
