<?php

namespace Firebase\JWT;

use ArrayObject;
use PHPUnit\Framework\TestCase;

class JWTTest extends TestCase
{
    /*
     * For compatibility with PHPUnit 4.8 and PHP < 5.6
     */
    public function setExpectedException($exceptionName, $message = '', $code = null)
    {
        if (method_exists($this, 'expectException')) {
            $this->expectException($exceptionName);
        } else {
            parent::setExpectedException($exceptionName, $message, $code);
        }
    }

    public function testDecodeFromPython()
    {
        $msg = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.Iio6aHR0cDovL2FwcGxpY2F0aW9uL2NsaWNreT9ibGFoPTEuMjMmZi5vbz00NTYgQUMwMDAgMTIzIg.E_U8X2YpMT5K1cEiT_3-IvBYfrdIFIeVYeOqre_Z5Cg';
        $this->assertEquals(
            JWT::decode($msg, new Key('my_key', 'HS256')),
            '*:http://application/clicky?blah=1.23&f.oo=456 AC000 123'
        );
    }

    public function testUrlSafeCharacters()
    {
        $encoded = JWT::encode('f?', 'a', 'HS256');
        $this->assertEquals('f?', JWT::decode($encoded, new Key('a', 'HS256')));
    }

    public function testMalformedUtf8StringsFail()
    {
        $this->setExpectedException('DomainException');
        JWT::encode(pack('c', 128), 'a', 'HS256');
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
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        JWT::decode($encoded, new Key('my_key', 'HS256'));
    }

    public function testBeforeValidTokenWithNbf()
    {
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        $payload = array(
            "message" => "abc",
            "nbf" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        JWT::decode($encoded, new Key('my_key', 'HS256'));
    }

    public function testBeforeValidTokenWithIat()
    {
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        $payload = array(
            "message" => "abc",
            "iat" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        JWT::decode($encoded, new Key('my_key', 'HS256'));
    }

    public function testValidToken()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + JWT::$leeway + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "exp" => time() - 20); // time in the past
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
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
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertEquals($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testValidTokenWithNbf()
    {
        $payload = array(
            "message" => "abc",
            "iat" => time(),
            "exp" => time() + 20, // time in the future
            "nbf" => time() - 20);
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithNbfLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "nbf"     => time() + 20); // not before in near (leeway) future
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertEquals($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testInvalidTokenWithNbfLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "nbf"     => time() + 65); // not before too far in future
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        JWT::decode($encoded, new Key('my_key', 'HS256'));
        JWT::$leeway = 0;
    }

    public function testValidTokenWithIatLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "iat"     => time() + 20); // issued in near (leeway) future
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertEquals($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testInvalidTokenWithIatLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "iat"     => time() + 65); // issued too far in future
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        JWT::decode($encoded, new Key('my_key', 'HS256'));
        JWT::$leeway = 0;
    }

    public function testInvalidToken()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->setExpectedException('Firebase\JWT\SignatureInvalidException');
        JWT::decode($encoded, new Key('my_key2', 'HS256'));
    }

    public function testNullKeyFails()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + JWT::$leeway + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->setExpectedException('InvalidArgumentException');
        JWT::decode($encoded, new Key(null, 'HS256'));
    }

    public function testEmptyKeyFails()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + JWT::$leeway + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->setExpectedException('InvalidArgumentException');
        JWT::decode($encoded, new Key('', 'HS256'));
    }

    public function testKIDChooser()
    {
        $keys = array(
            '1' => new Key('my_key', 'HS256'),
            '2' => new Key('my_key2', 'HS256')
        );
        $msg = JWT::encode('abc', $keys['1']->getKeyMaterial(), 'HS256', '1');
        $decoded = JWT::decode($msg, $keys);
        $this->assertEquals($decoded, 'abc');
    }

    public function testArrayAccessKIDChooser()
    {
        $keys = new ArrayObject(array(
            '1' => new Key('my_key', 'HS256'),
            '2' => new Key('my_key2', 'HS256'),
        ));
        $msg = JWT::encode('abc', $keys['1']->getKeyMaterial(), 'HS256', '1');
        $decoded = JWT::decode($msg, $keys);
        $this->assertEquals($decoded, 'abc');
    }

    public function testNoneAlgorithm()
    {
        $msg = JWT::encode('abc', 'my_key', 'HS256');
        $this->setExpectedException('UnexpectedValueException');
        JWT::decode($msg, new Key('my_key', 'none'));
    }

    public function testIncorrectAlgorithm()
    {
        $msg = JWT::encode('abc', 'my_key', 'HS256');
        $this->setExpectedException('UnexpectedValueException');
        JWT::decode($msg, new Key('my_key', 'RS256'));
    }

    public function testEmptyAlgorithm()
    {
        $msg = JWT::encode('abc', 'my_key', 'HS256');
        $this->setExpectedException('UnexpectedValueException');
        JWT::decode($msg, new Key('my_key', ''));
    }

    public function testAdditionalHeaders()
    {
        $msg = JWT::encode('abc', 'my_key', 'HS256', null, array('cty' => 'test-eit;v=1'));
        $this->assertEquals(JWT::decode($msg, new Key('my_key', 'HS256')), 'abc');
    }

    public function testInvalidSegmentCount()
    {
        $this->setExpectedException('UnexpectedValueException');
        JWT::decode('brokenheader.brokenbody', new Key('my_key', 'HS256'));
    }

    public function testInvalidSignatureEncoding()
    {
        $msg = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwibmFtZSI6ImZvbyJ9.Q4Kee9E8o0Xfo4ADXvYA8t7dN_X_bU9K5w6tXuiSjlUxx";
        $this->setExpectedException('UnexpectedValueException');
        JWT::decode($msg, new Key('secret', 'HS256'));
    }

    public function testHSEncodeDecode()
    {
        $msg = JWT::encode('abc', 'my_key', 'HS256');
        $this->assertEquals(JWT::decode($msg, new Key('my_key', 'HS256')), 'abc');
    }

    public function testRSEncodeDecode()
    {
        $privKey = openssl_pkey_new(array('digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA));
        $msg = JWT::encode('abc', $privKey, 'RS256');
        $pubKey = openssl_pkey_get_details($privKey);
        $pubKey = $pubKey['key'];
        $decoded = JWT::decode($msg, new Key($pubKey, 'RS256'));
        $this->assertEquals($decoded, 'abc');
    }

    public function testEdDsaEncodeDecode()
    {
        $keyPair = sodium_crypto_sign_keypair();
        $privKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));

        $payload = array('foo' => 'bar');
        $msg = JWT::encode($payload, $privKey, 'EdDSA');

        $pubKey = base64_encode(sodium_crypto_sign_publickey($keyPair));
        $decoded = JWT::decode($msg, new Key($pubKey, 'EdDSA'));
        $this->assertEquals('bar', $decoded->foo);
    }

    public function testInvalidEdDsaEncodeDecode()
    {
        $keyPair = sodium_crypto_sign_keypair();
        $privKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));

        $payload = array('foo' => 'bar');
        $msg = JWT::encode($payload, $privKey, 'EdDSA');

        // Generate a different key.
        $keyPair = sodium_crypto_sign_keypair();
        $pubKey = base64_encode(sodium_crypto_sign_publickey($keyPair));
        $this->setExpectedException('Firebase\JWT\SignatureInvalidException');
        JWT::decode($msg, new Key($pubKey, 'EdDSA'));
    }

    public function testRSEncodeDecodeWithPassphrase()
    {
        $privateKey = openssl_pkey_get_private(
            file_get_contents(__DIR__ . '/data/rsa-with-passphrase.pem'),
            'passphrase'
        );

        $jwt = JWT::encode('abc', $privateKey, 'RS256');
        $keyDetails = openssl_pkey_get_details($privateKey);
        $pubKey = $keyDetails['key'];
        $decoded = JWT::decode($jwt, new Key($pubKey, 'RS256'));
        $this->assertEquals($decoded, 'abc');
    }

    /**
     * @runInSeparateProcess
     * @dataProvider provideEncodeDecode
     */
    public function testEncodeDecode($privateKeyFile, $publicKeyFile, $alg)
    {
        $privateKey = file_get_contents($privateKeyFile);
        $payload = array('foo' => 'bar');
        $encoded = JWT::encode($payload, $privateKey, $alg);

        // Verify decoding succeeds
        $publicKey = file_get_contents($publicKeyFile);
        $decoded = JWT::decode($encoded, new Key($publicKey, $alg));

        $this->assertEquals('bar', $decoded->foo);
    }

    public function provideEncodeDecode()
    {
        return array(
            array(__DIR__ . '/data/ecdsa-private.pem', __DIR__ . '/data/ecdsa-public.pem', 'ES256'),
            array(__DIR__ . '/data/ecdsa384-private.pem', __DIR__ . '/data/ecdsa384-public.pem', 'ES384'),
            array(__DIR__ . '/data/rsa1-private.pem', __DIR__ . '/data/rsa1-public.pub', 'RS512'),
            array(__DIR__ . '/data/ed25519-1.sec', __DIR__ . '/data/ed25519-1.pub', 'EdDSA'),
        );
    }

    public function testEncodeDecodeWithResource()
    {
        $pem = file_get_contents(__DIR__ . '/data/rsa1-public.pub');
        $resource = openssl_pkey_get_public($pem);
        $privateKey = file_get_contents(__DIR__ . '/data/rsa1-private.pem');

        $payload = array('foo' => 'bar');
        $encoded = JWT::encode($payload, $privateKey, 'RS512');

        // Verify decoding succeeds
        $decoded = JWT::decode($encoded, new Key($resource, 'RS512'));

        $this->assertEquals('bar', $decoded->foo);
    }
}
