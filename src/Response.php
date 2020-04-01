<?php namespace davelip\NTLM\Proxy;

class Response
{
    /**
     * Returns a simple response based on a status code
     *
     * @param string           $message
     * @return Response
     */
    public static function error($message)
    {
        return new static("error", $message);
    }

    /**
     * The current response body
     *
     * @var string
     */
    protected $body = '';

    /**
     * Construct a new Response object
     *
     * @param string        $body
     * @return void
     */
    public function __construct($body)
    {
        $this->body = $body;
    }

    /**
     * Return the response body
     *
     * @return string
     */
    public function body()
    {
        return $this->body;
    }

    /**
     * Create a string out of the response data
     *
     * @return string
     */
    public function __toString()
    {
        return $this->body();
    }
}
