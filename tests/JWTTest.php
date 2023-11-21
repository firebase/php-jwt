<?php

namespace Firebase\JWT;

use ArrayObject;
use DomainException;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use stdClass;
use TypeError;
use UnexpectedValueException;

class JWTTest extends TestCase
{
    public function testUrlSafeCharacters()
    {
        $encoded = JWT::encode(['message' => 'f?'], 'a', 'HS256');
        $expected = new stdClass();
        $expected->message = 'f?';
        $this->assertEquals($expected, JWT::decode($encoded, new Key('a', 'HS256')));
    }

    public function testMalformedUtf8StringsFail()
    {
        $this->expectException(DomainException::class);
        JWT::encode(['message' => pack('c', 128)], 'a', 'HS256');
    }

    public function testMalformedJsonThrowsException()
    {
        $this->expectException(DomainException::class);
        JWT::jsonDecode('this is not valid JSON string');
    }

    public function testExpiredToken()
    {
        $this->expectException(ExpiredException::class);
        $payload = [
            'message' => 'abc',
            'exp' => time() - 20, // time in the past
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        JWT::decode($encoded, new Key('my_key', 'HS256'));
    }

    public function testBeforeValidTokenWithNbf()
    {
        $this->expectException(BeforeValidException::class);
        $payload = [
            'message' => 'abc',
            'nbf' => time() + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        JWT::decode($encoded, new Key('my_key', 'HS256'));
    }

    public function testBeforeValidTokenWithIat()
    {
        $this->expectException(BeforeValidException::class);
        $payload = [
            'message' => 'abc',
            'iat' => time() + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        JWT::decode($encoded, new Key('my_key', 'HS256'));
    }

    public function testValidToken()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + JWT::$leeway + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertSame($decoded->message, 'abc');
    }

    /**
     * @runInSeparateProcess
     */
    public function testValidTokenWithLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'exp' => time() - 20, // time in the past
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertSame($decoded->message, 'abc');
    }

    /**
     * @runInSeparateProcess
     */
    public function testExpiredTokenWithLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'exp' => time() - 70, // time far in the past
        ];
        $this->expectException(ExpiredException::class);
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertSame($decoded->message, 'abc');
    }

    public function testExpiredExceptionPayload()
    {
        $this->expectException(ExpiredException::class);
        $payload = [
            'message' => 'abc',
            'exp' => time() - 100, // time in the past
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        try {
            JWT::decode($encoded, new Key('my_key', 'HS256'));
        } catch (ExpiredException $e) {
            $exceptionPayload = (array) $e->getPayload();
            $this->assertEquals($exceptionPayload, $payload);
            throw $e;
        }
    }

    public function testBeforeValidExceptionPayload()
    {
        $this->expectException(BeforeValidException::class);
        $payload = [
            'message' => 'abc',
            'iat' => time() + 100, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        try {
            JWT::decode($encoded, new Key('my_key', 'HS256'));
        } catch (BeforeValidException $e) {
            $exceptionPayload = (array) $e->getPayload();
            $this->assertEquals($exceptionPayload, $payload);
            throw $e;
        }
    }

    public function testValidTokenWithNbf()
    {
        $payload = [
            'message' => 'abc',
            'iat' => time(),
            'exp' => time() + 20, // time in the future
            'nbf' => time() - 20
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertSame($decoded->message, 'abc');
    }

    /**
     * @runInSeparateProcess
     */
    public function testValidTokenWithNbfLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'nbf'     => time() + 20, // not before in near (leeway) future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertSame($decoded->message, 'abc');
    }

    /**
     * @runInSeparateProcess
     */
    public function testInvalidTokenWithNbfLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'nbf'     => time() + 65,  // not before too far in future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->expectException(BeforeValidException::class);
        $this->expectExceptionMessage('Cannot handle token with nbf prior to');
        JWT::decode($encoded, new Key('my_key', 'HS256'));
    }

    public function testValidTokenWithNbfIgnoresIat()
    {
        $payload = [
            'message' => 'abc',
            'nbf' => time() - 20, // time in the future
            'iat' => time() + 20, // time in the past
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertEquals('abc', $decoded->message);
    }

    public function testValidTokenWithNbfMicrotime()
    {
        $payload = [
            'message' => 'abc',
            'nbf' => microtime(true), // use microtime
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertEquals('abc', $decoded->message);
    }

    public function testInvalidTokenWithNbfMicrotime()
    {
        $this->expectException(BeforeValidException::class);
        $this->expectExceptionMessage('Cannot handle token with nbf prior to');
        $payload = [
            'message' => 'abc',
            'nbf' => microtime(true) + 20, // use microtime in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        JWT::decode($encoded, new Key('my_key', 'HS256'));
    }

    /**
     * @runInSeparateProcess
     */
    public function testValidTokenWithIatLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'iat'     => time() + 20, // issued in near (leeway) future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertSame($decoded->message, 'abc');
    }

    /**
     * @runInSeparateProcess
     */
    public function testInvalidTokenWithIatLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'iat'     => time() + 65, // issued too far in future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->expectException(BeforeValidException::class);
        $this->expectExceptionMessage('Cannot handle token with iat prior to');
        JWT::decode($encoded, new Key('my_key', 'HS256'));
    }

    public function testValidTokenWithIatMicrotime()
    {
        $payload = [
            'message' => 'abc',
            'iat' => microtime(true), // use microtime
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertEquals('abc', $decoded->message);
    }

    public function testInvalidTokenWithIatMicrotime()
    {
        $this->expectException(BeforeValidException::class);
        $this->expectExceptionMessage('Cannot handle token with iat prior to');
        $payload = [
            'message' => 'abc',
            'iat' => microtime(true) + 20, // use microtime in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        JWT::decode($encoded, new Key('my_key', 'HS256'));
    }

    public function testInvalidToken()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->expectException(SignatureInvalidException::class);
        JWT::decode($encoded, new Key('my_key2', 'HS256'));
    }

    public function testNullKeyFails()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + JWT::$leeway + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->expectException(TypeError::class);
        JWT::decode($encoded, new Key(null, 'HS256'));
    }

    public function testEmptyKeyFails()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + JWT::$leeway + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->expectException(InvalidArgumentException::class);
        JWT::decode($encoded, new Key('', 'HS256'));
    }

    public function testKIDChooser()
    {
        $keys = [
            '0' => new Key('my_key0', 'HS256'),
            '1' => new Key('my_key1', 'HS256'),
            '2' => new Key('my_key2', 'HS256')
        ];
        $msg = JWT::encode(['message' => 'abc'], $keys['0']->getKeyMaterial(), 'HS256', '0');
        $decoded = JWT::decode($msg, $keys);
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals($decoded, $expected);
    }

    public function testArrayAccessKIDChooser()
    {
        $keys = new ArrayObject([
            '0' => new Key('my_key0', 'HS256'),
            '1' => new Key('my_key1', 'HS256'),
            '2' => new Key('my_key2', 'HS256'),
        ]);
        $msg = JWT::encode(['message' => 'abc'], $keys['0']->getKeyMaterial(), 'HS256', '0');
        $decoded = JWT::decode($msg, $keys);
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals($decoded, $expected);
    }

    public function testNoneAlgorithm()
    {
        $msg = JWT::encode(['message' => 'abc'], 'my_key', 'HS256');
        $this->expectException(UnexpectedValueException::class);
        JWT::decode($msg, new Key('my_key', 'none'));
    }

    public function testIncorrectAlgorithm()
    {
        $msg = JWT::encode(['message' => 'abc'], 'my_key', 'HS256');
        $this->expectException(UnexpectedValueException::class);
        JWT::decode($msg, new Key('my_key', 'RS256'));
    }

    public function testEmptyAlgorithm()
    {
        $msg = JWT::encode(['message' => 'abc'], 'my_key', 'HS256');
        $this->expectException(InvalidArgumentException::class);
        JWT::decode($msg, new Key('my_key', ''));
    }

    public function testAdditionalHeaders()
    {
        $msg = JWT::encode(['message' => 'abc'], 'my_key', 'HS256', null, ['cty' => 'test-eit;v=1']);
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals(JWT::decode($msg, new Key('my_key', 'HS256')), $expected);
    }

    public function testInvalidSegmentCount()
    {
        $this->expectException(UnexpectedValueException::class);
        JWT::decode('brokenheader.brokenbody', new Key('my_key', 'HS256'));
    }

    public function testInvalidSignatureEncoding()
    {
        $msg = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwibmFtZSI6ImZvbyJ9.Q4Kee9E8o0Xfo4ADXvYA8t7dN_X_bU9K5w6tXuiSjlUxx';
        $this->expectException(UnexpectedValueException::class);
        JWT::decode($msg, new Key('secret', 'HS256'));
    }

    public function testHSEncodeDecode()
    {
        $msg = JWT::encode(['message' => 'abc'], 'my_key', 'HS256');
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals(JWT::decode($msg, new Key('my_key', 'HS256')), $expected);
    }

    public function testRSEncodeDecode()
    {
        $privKey = openssl_pkey_new(['digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $msg = JWT::encode(['message' => 'abc'], $privKey, 'RS256');
        $pubKey = openssl_pkey_get_details($privKey);
        $pubKey = $pubKey['key'];
        $decoded = JWT::decode($msg, new Key($pubKey, 'RS256'));
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals($decoded, $expected);
    }

    public function testEdDsaEncodeDecode()
    {
        $keyPair = sodium_crypto_sign_keypair();
        $privKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));

        $payload = ['foo' => 'bar'];
        $msg = JWT::encode($payload, $privKey, 'EdDSA');

        $pubKey = base64_encode(sodium_crypto_sign_publickey($keyPair));
        $decoded = JWT::decode($msg, new Key($pubKey, 'EdDSA'));
        $this->assertSame('bar', $decoded->foo);
    }

    public function testInvalidEdDsaEncodeDecode()
    {
        $keyPair = sodium_crypto_sign_keypair();
        $privKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));

        $payload = ['foo' => 'bar'];
        $msg = JWT::encode($payload, $privKey, 'EdDSA');

        // Generate a different key.
        $keyPair = sodium_crypto_sign_keypair();
        $pubKey = base64_encode(sodium_crypto_sign_publickey($keyPair));
        $this->expectException(SignatureInvalidException::class);
        JWT::decode($msg, new Key($pubKey, 'EdDSA'));
    }

    public function testRSEncodeDecodeWithPassphrase()
    {
        $privateKey = openssl_pkey_get_private(
            file_get_contents(__DIR__ . '/data/rsa-with-passphrase.pem'),
            'passphrase'
        );

        $jwt = JWT::encode(['message' => 'abc'], $privateKey, 'RS256');
        $keyDetails = openssl_pkey_get_details($privateKey);
        $pubKey = $keyDetails['key'];
        $decoded = JWT::decode($jwt, new Key($pubKey, 'RS256'));
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals($decoded, $expected);
    }

    public function testDecodesEmptyArrayAsObject()
    {
        $key = 'yma6Hq4XQegCVND8ef23OYgxSrC3IKqk';
        $payload = [];
        $jwt = JWT::encode($payload, $key, 'HS256');
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));
        $this->assertEquals((object) $payload, $decoded);
    }

    public function testDecodesArraysInJWTAsArray()
    {
        $key = 'yma6Hq4XQegCVND8ef23OYgxSrC3IKqk';
        $payload = ['foo' => [1, 2, 3]];
        $jwt = JWT::encode($payload, $key, 'HS256');
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));
        $this->assertSame($payload['foo'], $decoded->foo);
    }

    /**
     * @runInSeparateProcess
     * @dataProvider provideEncodeDecode
     */
    public function testEncodeDecode($privateKeyFile, $publicKeyFile, $alg)
    {
        $privateKey = file_get_contents($privateKeyFile);
        $payload = ['foo' => 'bar'];
        $encoded = JWT::encode($payload, $privateKey, $alg);

        // Verify decoding succeeds
        $publicKey = file_get_contents($publicKeyFile);
        $decoded = JWT::decode($encoded, new Key($publicKey, $alg));

        $this->assertSame('bar', $decoded->foo);
    }

    public function provideEncodeDecode()
    {
        return [
            [__DIR__ . '/data/ecdsa-private.pem', __DIR__ . '/data/ecdsa-public.pem', 'ES256'],
            [__DIR__ . '/data/ecdsa384-private.pem', __DIR__ . '/data/ecdsa384-public.pem', 'ES384'],
            [__DIR__ . '/data/rsa1-private.pem', __DIR__ . '/data/rsa1-public.pub', 'RS512'],
            [__DIR__ . '/data/ed25519-1.sec', __DIR__ . '/data/ed25519-1.pub', 'EdDSA'],
            [__DIR__ . '/data/secp256k1-private.pem', __DIR__ . '/data/secp256k1-public.pem', 'ES256K'],
        ];
    }

    public function testEncodeDecodeWithResource()
    {
        $pem = file_get_contents(__DIR__ . '/data/rsa1-public.pub');
        $resource = openssl_pkey_get_public($pem);
        $privateKey = file_get_contents(__DIR__ . '/data/rsa1-private.pem');

        $payload = ['foo' => 'bar'];
        $encoded = JWT::encode($payload, $privateKey, 'RS512');

        // Verify decoding succeeds
        $decoded = JWT::decode($encoded, new Key($resource, 'RS512'));

        $this->assertSame('bar', $decoded->foo);
    }

    public function testGetHeaders()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + JWT::$leeway + 20, // time in the future
        ];
        $headers = new stdClass();

        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        JWT::decode($encoded, new Key('my_key', 'HS256'), $headers);

        $this->assertEquals($headers->typ, 'JWT');
        $this->assertEquals($headers->alg, 'HS256');
    }

    public function testAdditionalHeaderOverrides()
    {
        $msg = JWT::encode(
            ['message' => 'abc'],
            'my_key',
            'HS256',
            'my_key_id',
            [
                'cty' => 'test-eit;v=1',
                'typ' => 'JOSE', // override type header
                'kid' => 'not_my_key_id', // should not override $key param
                'alg' => 'BAD', // should not override $alg param
            ]
        );
        $headers = new stdClass();
        JWT::decode($msg, new Key('my_key', 'HS256'), $headers);
        $this->assertEquals('test-eit;v=1', $headers->cty, 'additional field works');
        $this->assertEquals('JOSE', $headers->typ, 'typ override works');
        $this->assertEquals('my_key_id', $headers->kid, 'key param not overridden');
        $this->assertEquals('HS256', $headers->alg, 'alg param not overridden');
    }
}
