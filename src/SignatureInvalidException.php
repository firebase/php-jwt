<?php

namespace Firebase\JWT;

class SignatureInvalidException extends \UnexpectedValueException
{
    public const SIGNATURE_VERIFICATION_FAILED = 1;
}
