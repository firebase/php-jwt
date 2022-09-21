<?php

namespace Firebase\JWT;

class BeforeValidException extends \UnexpectedValueException
{
    public const NBF_PRIOR_TO_DATE = 1;
    public const IAT_PRIOR_TO_DATE = 2;
}
