<?php

namespace Firebase\JWT\Tests;

use \Firebase\JWT\JWT;
use \UnexpectedValueException;
use stdClass;

class HelperTest extends \PHPUnit_Framework_TestCase
{
    public function testSplit()
    {
        $token = array(
            "aud" => "https://firebase.com"
        );

        $jwt = JWT::encode($token, 'foo', 'HS256');

        $this->assertInternalType('array', JWT::split($jwt));
    }

    /**
     * @dataProvider invalidSplitValues
     */
    public function testInvalidSplit($value)
    {
        $this->setExpectedException('UnexpectedValueException');

        JWT::split($value);
    }

    public function invalidSplitValues()
    {
        return array(
            array(false),
            array(null),
            array('foo'),
            array('foo.bar'),
            array(1),
            array(array()),
            array(new stdClass),
        );
    }
}
