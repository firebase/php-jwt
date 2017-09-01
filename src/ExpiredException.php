<?php
namespace Firebase\JWT;

class ExpiredException extends \UnexpectedValueException
{
    /**
     * @var integer The HTTP status code
     */
    protected $code = 401;
}
