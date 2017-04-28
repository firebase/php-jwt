<?php
namespace Firebase\JWT;

class ExpiredException extends \UnexpectedValueException
{
	private $payload;

	public function setPayload($payload){
		$this->payload = $payload;
	}

	public function getPayload(){
		return $this->payload;
	}
}
