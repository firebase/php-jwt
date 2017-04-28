<?php
namespace Firebase\JWT;

class BeforeValidException extends \UnexpectedValueException
{
	private $payload;
	
	public function __construct($payload, $message, $code = 0, $cause = null){
		parent::__construct($message, $code, $cause);
		$this->payload = $payload;
	}
	
	public function getPayload(){
		return $this->payload;
	}
}
