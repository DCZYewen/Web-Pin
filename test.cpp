#include <iostream>
#include "webpin.hpp"

int main()
{
    sysinfo_t sysinfo;
    Pin_EnumSystemInfo(&sysinfo);
    std::cout << "CPU���ƣ�    " << sysinfo.cpu_name << std::endl;
    std::cout << "CPUλ����    " << sysinfo.cpu_bits << std::endl;
    std::cout << "OSλ����     " << sysinfo.os_bits << std::endl;
    std::cout << "�߼���������    " << sysinfo.cpu_logical_cores << std::endl;
    std::cout << "CPUռ���ʣ�   " << sysinfo.cpu_average_load << std::endl;
    std::cout << "�ܿ����ڴ棺   " << sysinfo.total_mem << std::endl;
    std::cout << "�ֿ����ڴ棺   " << sysinfo.free_mem << std::endl;
    std::cout << "������   ��   " << sysinfo.process_count << std::endl;

    std::cout << "------------------------------------" << std::endl;

    p_pid_t pids[MXPCS];
    int process_count = GetProcessList(pids);
    int process_now = 0;

    processinfo_t pi;

    while (Pin_EnumProcessInfo(pids, &pi, process_count, &process_now)) {
        printf("PID��%d \t ��������%s \t ����ռ���ڴ棺%lld Mib\t ����CPUռ��:%d\n", pi.proc_id
            , pi.proc_name, pi.proc_mem >> 10, pi.proc_cpu);
    }

    getchar();
}
