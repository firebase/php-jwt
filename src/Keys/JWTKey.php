<?php
namespace Firebase\JWT\Keys;

use Firebase\JWT\JWT;

class JWTKey
{
    /** @var string $alg */
    private $alg;

    /** @var string $keyMaterial */
    private $keyMaterial;

    /**
     * @param string $keyMaterial
     * @param string|array|null $alg
     */
    public function __construct($keyMaterial, $alg = null)
    {
        if (is_array($alg)) {
            $alg = self::guessAlgFromKeyMaterial($keyMaterial, $alg);
        } elseif (is_null($alg)) {
            $alg = self::guessAlgFromKeyMaterial($keyMaterial);
        }
        $this->keyMaterial = $keyMaterial;
        $this->alg = $alg;
    }

    /**
     * Is the header algorithm valid for this key?
     *
     * @param string $headerAlg
     * @return bool
     */
    public function isValidForAlg($headerAlg)
    {
        return JWT::constantTimeEquals($this->alg, $headerAlg);
    }

    /**
     * @return string
     */
    public function getKeyMaterial()
    {
        return $this->keyMaterial;
    }

    /**
     * This is a best-effort attempt to guess the algorithm for a given key
     * based on its contents.
     *
     * It will probably be wrong in a lot of corner cases.
     *
     * If it is, construct a JWTKey object and/or Keyring of JWTKey objects
     * with the correct algorithms.
     *
     * @param string $keyMaterial
     * @param array $candidates
     * @return string
     */
    public static function guessAlgFromKeyMaterial($keyMaterial, array $candidates = array())
    {
        $length = JWT::safeStrlen($keyMaterial);
        if ($length >= 720) {
            // RSA keys
            if (preg_match('#^-+BEGIN.+(PRIVATE|PUBLIC) KEY-+#', $keyMaterial)) {
                if (in_array('RS512', $candidates)) {
                    return 'RS512';
                }
                if (in_array('RS384', $candidates)) {
                    return 'RS384';
                }
                return 'RS256';
            }
        } elseif ($length >= 220) {
            // ECDSA private keys
            if (preg_match('#^-+BEGIN EC PRIVATE KEY-+#', $keyMaterial)) {
                if (in_array('ES512', $candidates)) {
                    return 'ES512';
                }
                if (in_array('ES384', $candidates)) {
                    return 'ES384';
                }
                return 'ES256';
            }
        } elseif ($length >= 170) {
            // ECDSA public keys
            if (preg_match('#^-+BEGIN EC PUBLICY-+#', $keyMaterial)) {
                if (in_array('ES512', $candidates)) {
                    return 'ES512';
                }
                if (in_array('ES384', $candidates)) {
                    return 'ES384';
                }
                return 'ES256';
            }
        } elseif ($length >= 40 && $length <= 88) {
            // Likely base64-encoded EdDSA key
            if (in_array('EdDSA', $candidates)) {
                return 'EdDSA';
            }
        }

        // Last resort: HMAC
        if (in_array('HS512', $candidates)) {
            return 'HS512';
        }
        if (in_array('HS384', $candidates)) {
            return 'HS384';
        }
        return 'HS256';
    }
}
