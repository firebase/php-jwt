<?php
namespace Firebase\JWT;

class ExpiredException extends \UnexpectedValueException
{

    /**
     * @var \DateInterval
     */
    protected $timeExpired;

    /**
     * Construct Class
     *
     * @param string $message
     * @param \DateInterval $timeExpired
     * @return void
     *
     * @author Filipe Voges <filipe.vogesh@gmail.com>
     * @since 2019-02-27
     * @version PHP-JWT v5.0.0
     */
    public function __construct(string $message, \DateInterval $timeExpired){
        parent::__construct($message);

        $this->timeExpired = $timeExpired;
    }

    /**
     * Get timeExpired
     *
     * @return \DateInterval
     *
     * @author Filipe Voges <filipe.vogesh@gmail.com>
     * @since 2019-02-27
     * @version PHP-JWT v5.0.0
     */
    public function getTimeExpired(){
        return $this->timeExpired;
    }

    /**
     * Returns the time the token is expired in a specific format
     *
     * @param string $format
     * @return string
     *
     * @author Filipe Voges <filipe.vogesh@gmail.com>
     * @since 2019-02-27
     * @version PHP-JWT v5.0.0
     */
    public function getTimeExpiredFormat(string $format = 'Y-m-d H:i:s'){
        return $this->timeExpired->format($format);
    }
}
