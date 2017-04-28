<?php
namespace Firebase\JWT;

class SignatureInvalidException extends \UnexpectedValueException
{  
	private $payload;
  
	public function setPayload($payload){
		$this->payload = $payload;
	}
  
	public function getPayload(){
		return $this->payload;
	}
}
