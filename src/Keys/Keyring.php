<?php
namespace Firebase\JWT\Keys;

use ArrayAccess;
use RuntimeException;

final class Keyring implements ArrayAccess
{
    /** @var array<string, JWTKey> $mapping */
    private $mapping;

    /**
     * @param array<string, JWTKey> $mapping
     */
    public function __construct(array $mapping = array())
    {
        $this->mapping = $mapping;
    }

    /**
     * @param string $keyId
     * @param JWTKey $key
     * @return $this
     */
    public function mapKeyId($keyId, JWTKey $key)
    {
        $this->mapping[$keyId] = $key;
        return $this;
    }

    /**
     * @param mixed $offset
     * @return bool
     */
    public function offsetExists($offset)
    {
        if (!is_string($offset)) {
            throw new RuntimeException('Type error: argument 1 must be a string');
        }
        return array_key_exists($offset, $this->mapping);
    }

    /**
     * @param mixed $offset
     * @return JWTKey
     */
    public function offsetGet($offset)
    {
        $value = $this->mapping[$offset];
        if (!($value instanceof JWTKey)) {
            throw new RuntimeException('Type error: return value not an instance of JWTKey');
        }
        return $value;
    }

    /**
     * @param string $offset
     * @param JWTKey $value
     */
    public function offsetSet($offset, $value)
    {
        if (!is_string($offset)) {
            throw new RuntimeException('Type error: argument 1 must be a string');
        }
        if (!($value instanceof JWTKey)) {
            throw new RuntimeException('Type error: argument 2 must be an instance of JWT');
        }
        $this->mapKeyId($offset, $value);
    }

    /**
     * @param string $offset
     */
    public function offsetUnset($offset)
    {
        if (!is_string($offset)) {
            throw new RuntimeException('Type error: argument 1 must be a string');
        }
        unset($this->mapping[$offset]);
    }
}
