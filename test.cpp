#include <iostream>
#include "webpin.hpp"

int main()
{
    sysinfo_t sysinfo;
    Pin_EnumSystemInfo(&sysinfo);
    std::cout << "CPU名称：    " << sysinfo.cpu_name << std::endl;
    std::cout << "CPU位数：    " << sysinfo.cpu_bits << std::endl;
    std::cout << "OS位数：     " << sysinfo.os_bits << std::endl;
    std::cout << "逻辑处理器：    " << sysinfo.cpu_logical_cores << std::endl;
    std::cout << "CPU占用率：   " << sysinfo.cpu_average_load << std::endl;
    std::cout << "总可用内存：   " << sysinfo.total_mem << std::endl;
    std::cout << "现可用内存：   " << sysinfo.free_mem << std::endl;
    std::cout << "进程数   ：   " << sysinfo.process_count << std::endl;

    std::cout << "------------------------------------" << std::endl;

    p_pid_t pids[MXPCS];
    int process_count = GetProcessList(pids);
    int process_now = 0;

    processinfo_t pi;

    while (Pin_EnumProcessInfo(pids, &pi, process_count, &process_now)) {
        printf("PID：%d \t 进程名：%s \t 进程占用内存：%lld Mib\t 进程CPU占用:%d\n", pi.proc_id
            , pi.proc_name, pi.proc_mem >> 10, pi.proc_cpu);
    }

    getchar();
}
