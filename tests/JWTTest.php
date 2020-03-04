<?php declare(strict_types=1);

namespace Firebase\JWT;

use ArrayObject;
use PHPUnit\Framework\TestCase;

final class JWTTest extends TestCase
{
    public static ?int $opensslVerifyReturnValue = null;

    public function testEncodeDecode(): void
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->assertEquals(JWT::decode($msg, 'my_key', ['HS256']), 'abc');
    }

    public function testDecodeFromPython(): void
    {
        $msg = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.Iio6aHR0cDovL2FwcGxpY2F0aW9uL2NsaWNreT9ibGFoPTEuMjMmZi5vbz00NTYgQUMwMDAgMTIzIg.E_U8X2YpMT5K1cEiT_3-IvBYfrdIFIeVYeOqre_Z5Cg';
        $this->assertEquals(JWT::decode($msg, 'my_key', ['HS256']), '*:http://application/clicky?blah=1.23&f.oo=456 AC000 123');
    }

    public function testUrlSafeCharacters(): void
    {
        $encoded = JWT::encode('f?', 'a');
        $this->assertEquals('f?', JWT::decode($encoded, 'a', ['HS256']));
    }

    public function testMalformedUtf8StringsFail(): void
    {
        $this->expectException('JsonException');
        JWT::encode(pack('c', 128), 'a');
    }

    public function testMalformedJsonThrowsException(): void
    {
        $this->expectException('JsonException');
        JWT::jsonDecode('this is not valid JSON string');
    }

    public function testExpiredToken(): void
    {
        $this->expectException('Firebase\JWT\ExpiredException');
        $payload = [
            "message" => "abc",
            "exp"     => time() - 20,// time in the past
        ];
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', ['HS256']);
    }

    public function testBeforeValidTokenWithNbf(): void
    {
        $this->expectException('Firebase\JWT\BeforeValidException');
        $payload = [
            "message" => "abc",
            "nbf"     => time() + 20,  // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', ['HS256']);
    }

    public function testBeforeValidTokenWithIat(): void
    {
        $this->expectException('Firebase\JWT\BeforeValidException');
        $payload = [
            "message" => "abc",
            "iat"     => time() + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', ['HS256']);
    }

    public function testValidToken(): void
    {
        $payload = [
            "message" => "abc",
            "exp"     => time() + JWT::$leeway + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', ['HS256']);
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithLeeway(): void
    {
        JWT::$leeway = 60;
        $payload     = [
            "message" => "abc",
            "exp"     => time() - 20, // time in the past
        ];
        $encoded     = JWT::encode($payload, 'my_key');
        $decoded     = JWT::decode($encoded, 'my_key', ['HS256']);
        $this->assertEquals($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testSetLeewayUpdateLeewayProperty(): void
    {
        JWT::setLeeway(100);
        $this->assertEquals(JWT::$leeway, 100);
        JWT::$leeway = 0;
    }

    public function testExpiredTokenWithLeeway(): void
    {
        JWT::$leeway = 60;
        $payload     = [
            "message" => "abc",
            "exp"     => time() - 70,
        ]; // time far in the past
        $this->expectException('Firebase\JWT\ExpiredException');
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', ['HS256']);
        $this->assertEquals($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testValidTokenWithList(): void
    {
        $payload = [
            "message" => "abc",
            "exp"     => time() + 20,
        ]; // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', ['HS256', 'HS512']);
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithNbf(): void
    {
        $payload = [
            "message" => "abc",
            "iat"     => time(),
            "exp"     => time() + 20, // time in the future
            "nbf"     => time() - 20,
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', ['HS256']);
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithNbfLeeway(): void
    {
        JWT::$leeway = 60;
        $payload     = [
            "message" => "abc",
            "nbf"     => time() + 20, // not before in near (leeway) future
        ];
        $encoded     = JWT::encode($payload, 'my_key');
        $decoded     = JWT::decode($encoded, 'my_key', ['HS256']);
        $this->assertEquals($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testInvalidTokenWithNbfLeeway(): void
    {
        JWT::$leeway = 60;
        $payload     = [
            "message" => "abc",
            "nbf"     => time() + 65, // not before too far in future
        ];
        $encoded     = JWT::encode($payload, 'my_key');
        $this->expectException('Firebase\JWT\BeforeValidException');
        JWT::decode($encoded, 'my_key', ['HS256']);
        JWT::$leeway = 0;
    }

    public function testValidTokenWithIatLeeway(): void
    {
        JWT::$leeway = 60;
        $payload     = [
            "message" => "abc",
            "iat"     => time() + 20, // issued in near (leeway) future
        ];
        $encoded     = JWT::encode($payload, 'my_key');
        $decoded     = JWT::decode($encoded, 'my_key', ['HS256']);
        $this->assertEquals($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testInvalidTokenWithIatLeeway(): void
    {
        JWT::$leeway = 60;
        $payload     = [
            "message" => "abc",
            "iat"     => time() + 65, // issued too far in future
        ];
        $encoded     = JWT::encode($payload, 'my_key');
        $this->expectException('Firebase\JWT\BeforeValidException');
        JWT::decode($encoded, 'my_key', ['HS256']);
        JWT::$leeway = 0;
    }

    public function testInvalidToken(): void
    {
        $payload = [
            "message" => "abc",
            "exp"     => time() + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $this->expectException('Firebase\JWT\SignatureInvalidException');
        JWT::decode($encoded, 'my_key2', ['HS256']);
    }

    public function testNullKeyFails(): void
    {
        $payload = [
            "message" => "abc",
            "exp"     => time() + JWT::$leeway + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $this->expectException('InvalidArgumentException');
        JWT::decode($encoded, null, ['HS256']);
    }

    public function testEmptyKeyFails(): void
    {
        $payload = [
            "message" => "abc",
            "exp"     => time() + JWT::$leeway + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key');
        $this->expectException('InvalidArgumentException');
        JWT::decode($encoded, '', ['HS256']);
    }

    public function testRSEncodeDecode(): void
    {
        $privKey = openssl_pkey_new([
            'digest_alg'       => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        $msg     = JWT::encode('abc', $privKey, 'RS256');
        $pubKey  = openssl_pkey_get_details($privKey);
        $pubKey  = $pubKey['key'];
        $decoded = JWT::decode($msg, $pubKey, ['RS256']);
        $this->assertEquals($decoded, 'abc');
    }

    public function testKIDChooser(): void
    {
        $keys    = ['1' => 'my_key', '2' => 'my_key2'];
        $msg     = JWT::encode('abc', $keys['1'], 'HS256', '1');
        $decoded = JWT::decode($msg, $keys, ['HS256']);
        $this->assertEquals($decoded, 'abc');
    }

    public function testArrayAccessKIDChooser(): void
    {
        $keys    = new ArrayObject(['1' => 'my_key', '2' => 'my_key2']);
        $msg     = JWT::encode('abc', $keys['1'], 'HS256', '1');
        $decoded = JWT::decode($msg, $keys, ['HS256']);
        $this->assertEquals($decoded, 'abc');
    }

    public function testNoneAlgorithm(): void
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->expectException('UnexpectedValueException');
        JWT::decode($msg, 'my_key', ['none']);
    }

    public function testIncorrectAlgorithm(): void
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->expectException('UnexpectedValueException');
        JWT::decode($msg, 'my_key', ['RS256']);
    }

    public function testMissingAlgorithm(): void
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->expectException('UnexpectedValueException');
        JWT::decode($msg, 'my_key');
    }

    public function testAdditionalHeaders(): void
    {
        $msg = JWT::encode('abc', 'my_key', 'HS256', null, ['cty' => 'test-eit;v=1']);
        $this->assertEquals(JWT::decode($msg, 'my_key', ['HS256']), 'abc');
    }

    public function testInvalidSegmentCount(): void
    {
        $this->expectException('UnexpectedValueException');
        JWT::decode('brokenheader.brokenbody', 'my_key', ['HS256']);
    }

    public function testInvalidSignatureEncoding(): void
    {
        $msg = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwibmFtZSI6ImZvbyJ9.Q4Kee9E8o0Xfo4ADXvYA8t7dN_X_bU9K5w6tXuiSjlUxx";
        $this->expectException('UnexpectedValueException');
        JWT::decode($msg, 'secret', ['HS256']);
    }

    public function testVerifyError(): void
    {
        $this->expectException('DomainException');
        $pkey                           = openssl_pkey_new();
        $msg                            = JWT::encode('abc', $pkey, 'RS256');
        self::$opensslVerifyReturnValue = -1;
        JWT::decode($msg, $pkey, ['RS256']);
    }

    /**
     * @runInSeparateProcess
     */
    public function testEncodeAndDecodeEcdsaToken(): void
    {
        $privateKey = file_get_contents(__DIR__ . '/ecdsa-private.pem');
        $payload    = ['foo' => 'bar'];
        $encoded    = JWT::encode($payload, $privateKey, 'ES256');

        // Verify decoding succeeds
        $publicKey = file_get_contents(__DIR__ . '/ecdsa-public.pem');
        $decoded   = JWT::decode($encoded, $publicKey, ['ES256']);

        $this->assertEquals('bar', $decoded->foo);
    }
}

/*
 * Allows the testing of openssl_verify with an error return value
 */
function openssl_verify(string $msg, string $signature, $key, $algorithm)
{
    if (null !== JWTTest::$opensslVerifyReturnValue)
    {
        return JWTTest::$opensslVerifyReturnValue;
    }

    return \openssl_verify($msg, $signature, $key, $algorithm);
}
