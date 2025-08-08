<?php

namespace Firebase\JWT;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use TypeError;

class Key
{
    /**
     * @param string|resource|OpenSSLAsymmetricKey|OpenSSLCertificate $keyMaterial
     * @param string $algorithm
     */
    public function __construct(
        #[\SensitiveParameter] private $keyMaterial,
        private string $algorithm
    ) {
        if (
            !\is_string($keyMaterial)
            && !$keyMaterial instanceof OpenSSLAsymmetricKey
            && !$keyMaterial instanceof OpenSSLCertificate
            && !\is_resource($keyMaterial)
        ) {
            throw new TypeError(
                'Key material must be a string, resource, or OpenSSLAsymmetricKey',
                JwtExceptionInterface::KEY_MATERIAL_IS_INVALID
            );
        }

        if (empty($keyMaterial)) {
            throw new InvalidArgumentException(
                'Key material must not be empty',
                JwtExceptionInterface::KEY_MATERIAL_IS_EMPTY
            );
        }

        if (empty($algorithm)) {
            throw new InvalidArgumentException(
                'Algorithm must not be empty',
                JwtExceptionInterface::KEY_ALGORITHM_IS_EMPTY
            );
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
     * @return string|resource|OpenSSLAsymmetricKey|OpenSSLCertificate
     */
    public function getKeyMaterial()
    {
        return $this->keyMaterial;
    }
}
