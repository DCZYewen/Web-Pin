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


## Note:
Web-Pin include a library LightLOG, which is originally developed by [Shenggan](https://github.com/Shenggan). This is an
advanced log library supports console and log-to-file(which could be a socket). I modified
it a little(added some switchs to close some of the features to keep the log clean and
tidy). Many thanks to Shenggan.

The httpserver functions and libraries are provided by [libhv](https://github.com/ithewei/libhv). libhv is a library like
libevent, libuv but provided more human-friendly interfaces and functions. Many thanks.

`webpin.hpp` is a header only libray provided monitor fuctions like
```
    sysinfo_t sysinfo;
    Pin_EnumSystemInfo(&sysinfo);
    
    processinfo_t pi;
    Pin_EnumProcessInfo(pids, &pi, process_count, &process_now)
```

For more usage infomation. See `test.cpp`.
