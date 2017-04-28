<?php
namespace Firebase\JWT;

class ExpiredException extends \UnexpectedValueException
{
	private $payload;

	public function __construct($payload = null){
		$this->payload = $payload;
	}

	public function getPayload(){
		return $this->payload;
	}
}
