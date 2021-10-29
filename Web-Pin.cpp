#include <iostream>
#include <stdio.h>
#include <hv/HttpServer.h>
#include <stdlib.h>
#include <stddef.h>
#include "webpin.hpp"
#include <vector>
#include "lightlog.h"

#define LLOG_NO_FILE 1
#define LLOG_NO_FUNC 1
#define LLOG_NO_LINE 1


int main(int argc, char* argv[]) {
	HttpService router;


	router.GET("/ping", [&router](HttpRequest* req, HttpResponse* resp) {
		LLOG(INFO) << "ClientIP: " << req->client_addr.ip << " " 
			<< "RequestUrl: " << req->url;
		return resp->String("pong");
		});
	//ping-pong site to dectect the server is active

	router.GET("/usage", [](HttpRequest* req, HttpResponse* resp) -> int {
		LLOG(INFO) << "ClientIP: " << req->client_addr.ip << " "
			<< "RequestUrl: " << req->url;

		sysinfo_t sysinfo;
		Pin_EnumSystemInfo(&sysinfo);

		resp->json["cpu_bits"] = sysinfo.cpu_bits;
		resp->json["os_bits"] = sysinfo.os_bits;
		resp->json["process_count"] = sysinfo.process_count;
		resp->json["total_mem"] = sysinfo.total_mem;
		resp->json["total_vmem"] = sysinfo.total_vmem;
		resp->json["free_mem"] = sysinfo.free_mem;
		resp->json["free_vmem"] = sysinfo.free_vmem;
		resp->json["cpu_logical_cores"] = sysinfo.cpu_logical_cores;
		resp->json["cpu_average_load"] = sysinfo.cpu_average_load;

		return 200;
		});



	router.GET("/process", [](HttpRequest* req, HttpResponse* resp) -> int {
		LLOG(INFO) << "ClientIP: " << req->client_addr.ip << " "
			<< "RequestUrl: " << req->url;

		p_pid_t pids[MXPCS];
		int process_count = GetProcessList(pids);
		int process_now = 0;

		processinfo_t pi;
		while (Pin_EnumProcessInfo(pids, &pi, process_count, &process_now)) {
			resp->json[std::to_string(pi.proc_id)] = "proc_name: " + std::string(pi.proc_name) + "|" +
				"proc_mem: " + std::to_string(pi.proc_mem) + "|" + "proc_cpu: " + std::to_string(pi.proc_cpu);
		}
		return 200;
		});

	http_server_t server;
	server.port = 8080;
	server.service = &router;
	http_server_run(&server);
	return 0;
}