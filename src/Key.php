<?php

namespace Firebase\JWT;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use TypeError;
use InvalidArgumentException;

class Key
{
    /**
     * @param string|OpenSSLAsymmetricKey|OpenSSLCertificate|array<mixed> $keyMaterial
     * @param string $algorithm
     */
    public function __construct(
        private string|OpenSSLAsymmetricKey|OpenSSLCertificate|array $keyMaterial,
        private string $algorithm
    ) {
        if (empty($keyMaterial)) {
            throw new InvalidArgumentException('Key material must not be empty');
        }

        if (empty($algorithm)) {
            throw new InvalidArgumentException('Algorithm must not be empty');
        }
    }

    /**
     * Return the algorithm valid for this key
     *
     * @return string
     */
    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * @return string|OpenSSLAsymmetricKey|OpenSSLCertificate|array<mixed>
     */
    public function getKeyMaterial(): string|OpenSSLAsymmetricKey|OpenSSLCertificate|array
    {
        return $this->keyMaterial;
    }
}
