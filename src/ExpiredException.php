<?php
namespace Firebase\JWT;

class ExpiredException extends \UnexpectedValueException
{
	private $payload;
	
	public function __construct($payload, $message, $code = 0, $previous = null){
		parent::__construct($message, $code, $previous);
		$this->payload = $payload;
	}
	
	public function getPayload(){
		return $this->payload;
	}
}
