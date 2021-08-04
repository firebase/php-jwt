<?php
namespace Firebase\JWT\Keys;

use PHPUnit\Framework\TestCase;

class JWTKeyTest extends TestCase
{
    public function testExpectedAlgGuess()
    {
        $eddsa = 'MpwwPe63YoDwAoO7EDBUOUb7J9lpdjt8vT+hfnLL39k=';
        $ecc384 = $this->getEcdsaPublicKey();
        $rsa = $this->getRsaPublicKey();
        $misc = 'maybe_use_paseto_instead';

        $this->assertSame(
            'RS512',
            JWTKey::guessAlgFromKeyMaterial($rsa, array('RS512'))
        );
        $this->assertSame(
            'RS384',
            JWTKey::guessAlgFromKeyMaterial($rsa, array('RS384'))
        );
        $this->assertSame(
            'RS256',
            JWTKey::guessAlgFromKeyMaterial($rsa, array('RS256'))
        );
        $this->assertSame(
            'RS256',
            JWTKey::guessAlgFromKeyMaterial($rsa)
        );
        $this->assertSame(
            'ES384',
            JWTKey::guessAlgFromKeyMaterial($ecc384, array('ES384'))
        );
        $this->assertSame(
            'ES256',
            JWTKey::guessAlgFromKeyMaterial($ecc384)
        );
        $this->assertSame(
            'EdDSA',
            JWTKey::guessAlgFromKeyMaterial($eddsa, array('EdDSA'))
        );
        $this->assertSame(
            'HS256',
            JWTKey::guessAlgFromKeyMaterial($eddsa)
        );
        $this->assertSame(
            'HS384',
            JWTKey::guessAlgFromKeyMaterial($misc, array('HS512'))
        );
        $this->assertSame(
            'HS384',
            JWTKey::guessAlgFromKeyMaterial($misc, array('HS384'))
        );
        $this->assertSame(
            'HS256',
            JWTKey::guessAlgFromKeyMaterial($misc, array('HS256'))
        );
        $this->assertSame(
            'HS256',
            JWTKey::guessAlgFromKeyMaterial($misc)
        );
    }

    public function getRsaPublicKey()
    {
        $privKey = openssl_pkey_new(array('digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA));
        $pubKey = openssl_pkey_get_details($privKey);
        return $pubKey['key'];
    }

    public function getEcdsaPublicKey()
    {
        $privKey = openssl_pkey_new(
            array(
                'curve_name' => 'secp384r1',
                'digest_alg' => 'sha384',
                'private_key_bits' => 384,
                'private_key_type' => OPENSSL_KEYTYPE_EC
            )
        );
        $pubKey = openssl_pkey_get_details($privKey);
        return $pubKey['key'];
    }
}
