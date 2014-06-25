<?php

class JWTTest extends PHPUnit_Framework_TestCase {
	function testEncodeDecode() {
		$msg = JWT::encode('abc', 'my_key');
		$this->assertEquals(JWT::decode($msg, 'my_key'), 'abc');
	}

	function testDecodeFromPython() {
		$msg = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.Iio6aHR0cDovL2FwcGxpY2F0aW9uL2NsaWNreT9ibGFoPTEuMjMmZi5vbz00NTYgQUMwMDAgMTIzIg.E_U8X2YpMT5K1cEiT_3-IvBYfrdIFIeVYeOqre_Z5Cg';
		$this->assertEquals(
			JWT::decode($msg, 'my_key'),
			'*:http://application/clicky?blah=1.23&f.oo=456 AC000 123'
		);
	}

	function testUrlSafeCharacters() {
		$encoded = JWT::encode('f?', 'a');
		$this->assertEquals('f?', JWT::decode($encoded, 'a'));
	}

	function testMalformedUtf8StringsFail() {
		$this->setExpectedException('DomainException');
		JWT::encode(pack('c', 128), 'a');
	}

	function testMalformedJsonThrowsException() {
		$this->setExpectedException('DomainException');
		JWT::jsonDecode('this is not valid JSON string');
	}

	function testExpiredToken() {
		$this->setExpectedException('UnexpectedValueException');
		$payload = array(
			"message" => "abc",
			"exp" => time() - 20); // time in the past
		$encoded = JWT::encode($payload, 'my_key');
		JWT::decode($encoded);
	}

	function testValidToken() {
		$payload = array(
			"message" => "abc",
			"exp" => time() + 20); // time in the future
		$encoded = JWT::encode($payload, 'my_key');
		$decoded = JWT::decode($encoded, 'my_key');
		$this->assertEquals($decoded->message, 'abc');
	}

	function testRSEncodeDecode() {
		$privKey = openssl_pkey_new(array('digest_alg' => 'sha256',
			'private_key_bits' => 1024,
			'private_key_type' => OPENSSL_KEYTYPE_RSA));
		$msg = JWT::encode('abc', $privKey, 'RS256');
		$pubKey = openssl_pkey_get_details($privKey);
		$pubKey = $pubKey['key'];
		$decoded = JWT::decode($msg, $pubKey, true);
		$this->assertEquals($decoded, 'abc');
	}

	function testKIDChooser() {
		$keys = array('1' => 'my_key', '2' => 'my_key2');
		$msg = JWT::encode('abc', $keys['1'], 'HS256', '1');
		$decoded = JWT::decode($msg, $keys, true);
		$this->assertEquals($decoded, 'abc');
	}

}

?>
