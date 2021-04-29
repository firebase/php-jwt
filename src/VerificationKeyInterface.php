<?php

namespace Firebase\JWT;

use stdClass;

/**
 * Provide a specific key for signature verification based on token header.
 */
interface VerificationKeyInterface
{
    /**
     * Make an informed decision of which key to use, based on the JOSE header
     * in its entirety.
     *
     * @param stdClass $header JOSE header containing alg and optional values
     *                         (kid, jku, jwk, etc.)
     *
     * @throws UnexpectedValueException
     * @return string
     */
    public function verificationKey(stdClass $header);
}
