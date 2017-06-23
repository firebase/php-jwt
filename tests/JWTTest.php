<?php
namespace Firebase\JWT;

use ArrayObject;
use PHPUnit_Framework_TestCase;

class JWTTest extends PHPUnit_Framework_TestCase
{
    public static $opensslVerifyReturnValue;

    public function testEncodeDecode()
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->assertEquals(JWT::decode($msg, 'my_key', array('HS256')), 'abc');
    }

    public function testDecodeFromPython()
    {
        $msg = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.Iio6aHR0cDovL2FwcGxpY2F0aW9uL2NsaWNreT9ibGFoPTEuMjMmZi5vbz00NTYgQUMwMDAgMTIzIg.E_U8X2YpMT5K1cEiT_3-IvBYfrdIFIeVYeOqre_Z5Cg';
        $this->assertEquals(
            JWT::decode($msg, 'my_key', array('HS256')),
            '*:http://application/clicky?blah=1.23&f.oo=456 AC000 123'
        );
    }

    public function testUrlSafeCharacters()
    {
        $encoded = JWT::encode('f?', 'a');
        $this->assertEquals('f?', JWT::decode($encoded, 'a', array('HS256')));
    }

    public function testMalformedUtf8StringsFail()
    {
        $this->setExpectedException('DomainException');
        JWT::encode(pack('c', 128), 'a');
    }

    public function testMalformedJsonThrowsException()
    {
        $this->setExpectedException('DomainException');
        JWT::jsonDecode('this is not valid JSON string');
    }

    public function testExpiredToken()
    {
        $this->setExpectedException('Firebase\JWT\ExpiredException');
        $payload = array(
            "message" => "abc",
            "exp" => time() - 20); // time in the past
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', array('HS256'));
    }

    public function testBeforeValidTokenWithNbf()
    {
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        $payload = array(
            "message" => "abc",
            "nbf" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', array('HS256'));
    }

    public function testBeforeValidTokenWithIat()
    {
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        $payload = array(
            "message" => "abc",
            "iat" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', array('HS256'));
    }

    public function testValidToken()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + JWT::$leeway + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "exp" => time() - 20); // time in the past
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testExpiredTokenWithLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "exp" => time() - 70); // time far in the past
        $this->setExpectedException('Firebase\JWT\ExpiredException');
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testValidTokenWithList()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256', 'HS512'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithNbf()
    {
        $payload = array(
            "message" => "abc",
            "iat" => time(),
            "exp" => time() + 20, // time in the future
            "nbf" => time() - 20);
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithNbfLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "nbf"     => time() + 20); // not before in near (leeway) future
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testInvalidTokenWithNbfLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "nbf"     => time() + 65); // not before too far in future
        $encoded = JWT::encode($payload, 'my_key');
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        JWT::$leeway = 0;
    }

    public function testValidTokenWithIatLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "iat"     => time() + 20); // issued in near (leeway) future
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testInvalidTokenWithIatLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "iat"     => time() + 65); // issued too far in future
        $encoded = JWT::encode($payload, 'my_key');
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        JWT::$leeway = 0;
    }

    public function testInvalidToken()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $this->setExpectedException('Firebase\JWT\SignatureInvalidException');
        $decoded = JWT::decode($encoded, 'my_key2', array('HS256'));
    }

    public function testNullKeyFails()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + JWT::$leeway + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $this->setExpectedException('InvalidArgumentException');
        $decoded = JWT::decode($encoded, null, array('HS256'));
    }

    public function testEmptyKeyFails()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + JWT::$leeway + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $this->setExpectedException('InvalidArgumentException');
        $decoded = JWT::decode($encoded, '', array('HS256'));
    }

    public function testRSEncodeDecode()
    {
        $privKey = openssl_pkey_new(array('digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA));
        $msg = JWT::encode('abc', $privKey, 'RS256');
        $pubKey = openssl_pkey_get_details($privKey);
        $pubKey = $pubKey['key'];
        $decoded = JWT::decode($msg, $pubKey, array('RS256'));
        $this->assertEquals($decoded, 'abc');
    }

    public function testKIDChooser()
    {
        $keys = array('1' => 'my_key', '2' => 'my_key2');
        $msg = JWT::encode('abc', $keys['1'], 'HS256', '1');
        $decoded = JWT::decode($msg, $keys, array('HS256'));
        $this->assertEquals($decoded, 'abc');
    }

    public function testArrayAccessKIDChooser()
    {
        $keys = new ArrayObject(array('1' => 'my_key', '2' => 'my_key2'));
        $msg = JWT::encode('abc', $keys['1'], 'HS256', '1');
        $decoded = JWT::decode($msg, $keys, array('HS256'));
        $this->assertEquals($decoded, 'abc');
    }

    public function testNoneAlgorithm()
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->setExpectedException('UnexpectedValueException');
        JWT::decode($msg, 'my_key', array('none'));
    }

    public function testIncorrectAlgorithm()
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->setExpectedException('UnexpectedValueException');
        JWT::decode($msg, 'my_key', array('RS256'));
    }

    public function testMissingAlgorithm()
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->setExpectedException('UnexpectedValueException');
        JWT::decode($msg, 'my_key');
    }

    public function testAdditionalHeaders()
    {
        $msg = JWT::encode('abc', 'my_key', 'HS256', null, array('cty' => 'test-eit;v=1'));
        $this->assertEquals(JWT::decode($msg, 'my_key', array('HS256')), 'abc');
    }

    public function testInvalidEmptyIssuerDecode()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'));
        $this->setExpectedException('InvalidIssuerException');
        JWT::decode($msg, 'my_key', array('HS256'), array('issuer' => ''));
    }

    public function testInvalidIssuer()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'), array('issuer' => 'another.example.com'));
        $this->setExpectedException('InvalidIssuerException');
        JWT::decode($msg, 'my_key', array('HS256'), array('issuer' => 'example.com'));
    }

    public function testValidEmptyIssuerPayload()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'), array('issuer' => ''));
        $decoded = JWT::decode($msg, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidIssuer()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'), array('issuer' => 'example.com'));
        $decoded = JWT::decode($msg, 'my_key', array('HS256'), array('issuer' => 'example.com'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testInvalidEmptySubjectDecode()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'));
        $this->setExpectedException('InvalidSubjectException');
        JWT::decode($msg, 'my_key', array('HS256'), array('subject' => ''));
    }

    public function testInvalidSubject()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'), array('subject' => 'NotSubject'));
        $this->setExpectedException('InvalidSubjectException');
        JWT::decode($msg, 'my_key', array('HS256'), array('subject' => 'Subject'));
    }

    public function testValidEmptySubjectPayload()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'), array('subject' => ''));
        $decoded = JWT::decode($msg, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidSubject()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'), array('subject' => 'Subject'));
        $decoded = JWT::decode($msg, 'my_key', array('HS256'), array('subject' => 'Subject'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testInvalidEmptyAudienceDecode()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'));
        $this->setExpectedException('InvalidAudienceException');
        JWT::decode($msg, 'my_key', array('HS256'), array('audience' => array('audience')));
    }

    public function testInvalidAudience()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'), array('audience' => array('Audience1', 'Audience2')));
        $this->setExpectedException('InvalidAudienceException');
        JWT::decode($msg, 'my_key', array('HS256'), array('audience' => 'Audience3'));
    }

    public function testValidEmptyAudiencePayload()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'), array('audience' => array('audience')));
        $decoded = JWT::decode($msg, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidAudience()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'), array('audience' => array('Audience1', 'Audience2')));
        $decoded = JWT::decode($msg, 'my_key', array('HS256'), array('audience' => 'Audience2'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testInvalidEmptyJWTIdDecode()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'));
        $this->setExpectedException('InvalidJWTIdException');
        JWT::decode($msg, 'my_key', array('HS256'), array('jwtid' => 'userID'));
    }

    public function testInvalidJWTId()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'), array('jwtid' => 'userID'));
        $this->setExpectedException('InvalidJWTIdException');
        JWT::decode($msg, 'my_key', array('HS256'), array('jwtid' => 'notMyUserID'));
    }

    public function testValidEmptyJWTIdPayload()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'), array('jwtid' => 'userID'));
        $decoded = JWT::decode($msg, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidJWTId()
    {
        $msg = JWT::encode(array('message' => 'abc'), 'my_key', 'HS256', NULL, array('cty' => 'test-eit;v=1'), array('jwtid' => 'userID'));
        $decoded = JWT::decode($msg, 'my_key', array('HS256'), array('jwtid' => 'userID'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testInvalidSegmentCount()
    {
        $this->setExpectedException('UnexpectedValueException');
        JWT::decode('brokenheader.brokenbody', 'my_key', array('HS256'));
    }

    public function testInvalidSignatureEncoding()
    {
        $msg = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwibmFtZSI6ImZvbyJ9.Q4Kee9E8o0Xfo4ADXvYA8t7dN_X_bU9K5w6tXuiSjlUxx";
        $this->setExpectedException('UnexpectedValueException');
        JWT::decode($msg, 'secret', array('HS256'));
    }

    public function testVerifyError()
    {
        $this->setExpectedException('DomainException');
        $pkey = openssl_pkey_new();
        $msg = JWT::encode('abc', $pkey, 'RS256');
        self::$opensslVerifyReturnValue = -1;
        JWT::decode($msg, $pkey, array('RS256'));
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
