<?php

class JWTTest extends PHPUnit_Framework_TestCase
{
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
        $this->setExpectedException('ExpiredException');
        $payload = array(
            "message" => "abc",
            "exp" => time() - 20); // time in the past
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', array('HS256'));
    }

    public function testBeforeValidTokenWithNbf()
    {
        $this->setExpectedException('BeforeValidException');
        $payload = array(
            "message" => "abc",
            "nbf" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', array('HS256'));
    }

    public function testBeforeValidTokenWithIat()
    {
        $this->setExpectedException('BeforeValidException');
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
            "exp" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
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

    public function testInvalidToken()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $this->setExpectedException('SignatureInvalidException');
        $decoded = JWT::decode($encoded, 'my_key2', array('HS256'));
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

    public function testNoneAlgorithm()
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->setExpectedException('DomainException');
        JWT::decode($msg, 'my_key', array('none'));
    }

    public function testIncorrectAlgorithm()
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->setExpectedException('DomainException');
        JWT::decode($msg, 'my_key', array('RS256'));
    }

    public function testMissingAlgorithm()
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->setExpectedException('DomainException');
        JWT::decode($msg, 'my_key');
    }
}
