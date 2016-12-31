<?php

namespace Firebase\JWT\Tests;

use \Firebase\JWT\JWT;
use stdClass;

class HeaderTest extends \PHPUnit_Framework_TestCase
{
    public function testGetHeader()
    {
        $key = 'foo';
        $alg = 'HS256';

        $token = array(
            "aud" => "https://firebase.com"
        );

        $jwt = JWT::encode($token, $key, $alg);

        $obj = new stdClass;
        $obj->typ = 'JWT';
        $obj->alg = $alg;

        $this->assertEquals($obj, JWT::header($jwt));
    }
}
