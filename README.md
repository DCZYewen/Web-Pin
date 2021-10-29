# Web-Pin
A probe to monitor server status.

For the first time, I wanted a probe that are not very "chumbby" to monitor my servers'
status. But when the development gets deeper, it has become more and more complicated.

But anyway, Web-Pin can support single server, multi-threaded, Windows® only. But it will
be more copelete later.

When compile and run, Web-Pin will listen to 127.0.0.0:8080. You can access it via browser.
When compile as x86 but OS is x86_64, Web-Pin will represent every process running at x64
as "Not enough privilege". This is could be looked up at WinErr.h error code 299.

```
curl http://localhost:8080/ping -> pong
curl http://localhost:8080/process
curl http://localhost:8080/usage
```
