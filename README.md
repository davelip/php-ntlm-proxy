# ntlm-proxy in pure PHP

Freely inspired by: 

* https://github.com/Legrandin/PyAuthenNTLM2
* https://github.com/loune/php-ntlm/


It's support only Domain Controller proxy.


## Installation

1. git clone https://github.com/davelip/php-ntlm-proxy.git
1. composer install
1. cp .env.example .env
1. modify .env with your own configurations
1. run the server: php server

You can test the connection in two ways:

 # netstat -plunt | grep `port`
If you see a row in the output your server is running

 # telnet localhost `port`
If you enter in interactive mode your server is running and you are communicating with him. Try to write something like `type1 123 AAAAA` and press Enter. You should get something like `Generic errorConnection closed by foreign host.`

For a production environment I suggest to install a tool like supervisord or to run php-ntlm-proxy like a system service (see next paragraphs).


### Supervisord

http://supervisord.org/

Install it and configure your server.

```
```
[program:php-ntlm-proxy]
command=/usr/bin/php server
directory=/path/to/php-ntlm-proxy
stderr_logfile=/var/log/supervisor/php-ntlm-proxy-stderr.log
stdout_logfile=/var/log/supervisor/php-ntlm-proxy-stdout.log
```
```

### Running like a system service

https://maslosoft.com/blog/2019/07/10/running-php-script-as-a-system-service-in-ubuntu/


## Usage

When the server is correctly configured and up and running you can communicate with him throught socket to validate NTLM credentials.

See the php example in `example/auth.php`.
