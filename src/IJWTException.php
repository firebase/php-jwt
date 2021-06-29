<?php
namespace Firebase\JWT;

interface IJWTException
{
    /**
     * Get the payload that caused this exception.
     *
     * @return object
     */
    public function getPayload();
}
