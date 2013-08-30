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
}

?>
