<?php

namespace Firebase\JWT;

class ExpiredException extends \UnexpectedValueException
{
    public const TOKEN_EXPIRED = 1;
}
