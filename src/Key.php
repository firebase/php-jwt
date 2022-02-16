<?php

namespace Firebase\JWT;

use OpenSSLAsymmetricKey;
use TypeError;
use InvalidArgumentException;

class Key
{
    /**
     * @param string|OpenSSLAsymmetricKey $keyMaterial
     * @param string $algorithm
     */
    public function __construct(
        private string|OpenSSLAsymmetricKey $keyMaterial,
        private string $algorithm
    ) {
        if (
            !is_string($keyMaterial)
            && !$keyMaterial instanceof OpenSSLAsymmetricKey
        ) {
            throw new TypeError('Key material must be a string or OpenSSLAsymmetricKey');
        }

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
     * @return string|OpenSSLAsymmetricKey
     */
    public function getKeyMaterial(): mixed
    {
        return $this->keyMaterial;
    }
}
