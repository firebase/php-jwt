<?php

namespace Firebase\JWT\Tests;

use \Firebase\JWT\JWT;
use stdClass;

class PayloadTest extends \PHPUnit_Framework_TestCase
{
    public function testGetPayload()
    {
        $token = array(
            "aud" => "https://firebase.com"
        );

        $jwt = JWT::encode($token, 'foo', 'HS256');

        $obj = new stdClass;
        $obj->aud = 'https://firebase.com';

        $this->assertEquals($obj, JWT::payload($jwt));
    }
}
