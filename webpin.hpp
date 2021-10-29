#pragma once
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <map>
#include <memory>
#include <string>
#include <cstring>
#include <stddef.h>
int GetCPUBits(void);

typedef struct _sysinfo_t {
    int32_t cpu_bits;
    int32_t os_bits;

    int32_t process_count;

    /*
    These number is in KiB, not in bytes
    */
    int32_t total_mem;
    int32_t total_vmem;
    int32_t free_mem;
    int32_t free_vmem;

    int16_t cpu_logical_cores;
    int16_t cpu_average_load;
    char*   cpu_name;

    void* reserved;
    
    _sysinfo_t();
    ~_sysinfo_t();

} sysinfo_t;

#ifdef _WIN32
#include <Windows.h>
typedef DWORD p_pid_t;
#else
#include <sys/types.h>
#endif

class basic_pi_t {
public:
    /*
    basic processinfo _t
    Contains process name, process memory, process cpu usage,
    process id(pid) and functions to acquire the proper information
    */

public:
    char*   proc_name;
    int64_t proc_mem;
    int32_t proc_cpu;
    p_pid_t   proc_id;

    basic_pi_t();
    ~basic_pi_t();

protected:
    virtual void AcquirePInformation() {};//this function is implemented by its sub-class

};
#define MXLPN 128
#define MXPCS 1024
//Max process count is MSPCS

basic_pi_t::basic_pi_t() {
    proc_mem = 0;
    proc_cpu = 0;
    proc_id = 0;
    proc_name = (char*)malloc(sizeof(char) * MXLPN);
    /*
    The maximum length of procname is MXLP(max length of process name)
    */
}

basic_pi_t::~basic_pi_t() {
    free(proc_name);
}


_sysinfo_t::_sysinfo_t(void) {
    cpu_bits = 8;
    os_bits = 8;

    process_count = 0;

    total_mem = 0;
    total_vmem = 0;
    free_mem = 0;
    free_vmem = 0;

    cpu_logical_cores = 1;
    cpu_average_load = 0;

    reserved = NULL;

    cpu_name = (char*)malloc(sizeof(char) * 256);
}

_sysinfo_t::~_sysinfo_t(void) {
    free(cpu_name);
}


#if defined(WIN32) || defined(__NT__)
#include <Windows.h>
#include <tchar.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <comutil.h>
#include <psapi.h>
#include <winnt.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment( lib, "psapi.lib" )

/*
These headers are used to provide Windows® specific function and marcos.
WMI and Win32 APIs are used in this case.
*/

VOID SafeGetNativeSystemInfo(__out LPSYSTEM_INFO lpSystemInfo)
{
    if (NULL == lpSystemInfo)    return;
    typedef VOID(WINAPI* LPFN_GetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
    LPFN_GetNativeSystemInfo fnGetNativeSystemInfo = (LPFN_GetNativeSystemInfo)GetProcAddress(GetModuleHandle(_T("kernel32")), "GetNativeSystemInfo");;
    if (NULL != fnGetNativeSystemInfo)
    {
        fnGetNativeSystemInfo(lpSystemInfo);
    }
    else
    {
        GetSystemInfo(lpSystemInfo);
    }
}

int GetCPUBits(void) {
	SYSTEM_INFO si;
	SafeGetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) {
		return 64;
	}
	return 32;
}

VOID GenerateErrStr(const char* str, HRESULT hres , char* ret) {
    std::string t = std::string(str) + std::to_string(hres);

#ifdef _WEBPIN_DBG
    strcpy_s(ret , t.size() , t.cstr());
#endif

    return;
}

int WMICALLER(void* data , char* error) {
    /*
    void* data is a buffer used to store data retrived from WMI.
    char* error is for passing the error information outside the func.
    which currently does nothing, just pass a NULL pointer into it.
    */
    HRESULT hres;

    sysinfo_t * i_result = (sysinfo_t*)data;

    /*
    this pointer is not doing anything, when you needed error
    information, alloc the memory of err, and do remember to free it
    */

    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        GenerateErrStr("Failed to initialize COM library. Error code:", hres, error);
        return 1;                  // Program has failed.
    }

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------

    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );


    if (FAILED(hres))
    {
        GenerateErrStr("Failed to initialize security. Error code =", hres, error);
        CoUninitialize();
        return 1;                    // Program has failed.
    }

    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------

    IWbemLocator* pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        GenerateErrStr("Failed to create IWbemLocator object. Err code:", hres, error);
        CoUninitialize();
        return 1;                 // Program has failed.
    }

    // Step 4: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method

    IWbemServices* pSvc = NULL;

    // Connect to the root\cimv2 namespace with
    // the current user and obtain pointer pSvc
    // to make IWbemServices calls.
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
        NULL,                    // User name. NULL = current user
        NULL,                    // User password. NULL = current
        0,                       // Locale. NULL indicates current
        NULL,                    // Security flags.
        0,                       // Authority (for example, Kerberos)
        0,                       // Context object 
        &pSvc                    // pointer to IWbemServices proxy
    );

    if (FAILED(hres))
    {
        GenerateErrStr("Could not connect. Error code:", hres, error);
        pLoc->Release();
        CoUninitialize();
        return 1;                // Program has failed.
    }

    // Connecting to ROOT\\CIMV2 WMI namespace


    // Step 5: --------------------------------------------------
    // Set security levels on the proxy -------------------------

    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres))
    {
        GenerateErrStr("Could not set proxy blanket. Error code:", hres, error);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;               // Program has failed.
    }

    // Step 6: --------------------------------------------------
    // Use the IWbemServices pointer to make requests of WMI ----

    // For example, get the name of the operating system
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_OperatingSystem"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        GenerateErrStr("Query for operating system name failed. Error code:", hres, error);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;               // Program has failed.
    }

    // Step 7: -------------------------------------------------
    // Get the data from the query in step 6 -------------------

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
            &pclsObj, &uReturn);

        if (0 == uReturn)
        {
            break;
        }

        VARIANT vtProp;


        hr = pclsObj->Get(L"OSArchitecture", 0, &vtProp, 0, 0);
        auto _internal = std::wstring((wchar_t*)vtProp.bstrVal);
        char _temp_str[3] = { _internal[0] , _internal[1] , '\0' };
        i_result->os_bits = atoi(_temp_str);

        hr = pclsObj->Get(L"FreePhysicalMemory", 0, &vtProp, 0, 0);
        _internal = std::wstring((wchar_t*)vtProp.bstrVal);
        i_result->free_mem = std::stoi(_internal);

        hr = pclsObj->Get(L"FreeVirtualMemory", 0, &vtProp, 0, 0);
        _internal = std::wstring((wchar_t*)vtProp.bstrVal);
        i_result->free_vmem = std::stoi(_internal);
        
        hr = pclsObj->Get(L"TotalVisibleMemorySize", 0, &vtProp, 0, 0);
        _internal = std::wstring((wchar_t*)vtProp.bstrVal);
        i_result->total_mem = std::stoi(_internal);

        hr = pclsObj->Get(L"TotalVirtualMemorySize", 0, &vtProp, 0, 0);
        _internal = std::wstring((wchar_t*)vtProp.bstrVal);
        i_result->total_vmem = std::stoi(_internal);

        hr = pclsObj->Get(L"NumberOfProcesses", 0, &vtProp, 0, 0);
        i_result->process_count = (int)vtProp.intVal;

        VariantClear(&vtProp);

        //Win32_OperatingSystem class is now queried.

        /*
        Win32_OperatingSystem

        OSArchitecture
        FreePhysicalMemory
        FreeVirtualMemory
        TotalVirtualMemorySize
        TotalVisibleMemorySize
        NumberOfProcesses
        */
        pclsObj->Release();
    }

    /*
    Temporarily cleaning up procedures
    */

    pEnumerator->Release();

    // Redo Step 6, but this time query class is Win32_Processor
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_Processor"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        GenerateErrStr("Query for processor information name failed. Error code:", hres, error);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;               // Program has failed.
    }

    // Step 7: -------------------------------------------------
    // Get the data from the query in step 6 -------------------

    //IWbemClassObject* pclsObj = NULL;
    //ULONG uReturn = 0;
    //Initialized up above, but for understanding, I keeped it here.

    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
            &pclsObj, &uReturn);

        if (0 == uReturn)
        {
            break;
        }

        VARIANT vtProp;

        hr = pclsObj->Get(L"NumberOfLogicalProcessors", 0, &vtProp, 0, 0);
        i_result->cpu_logical_cores = (int)vtProp.intVal;

        hr = pclsObj->Get(L"LoadPercentage", 0, &vtProp, 0, 0);
        i_result->cpu_average_load = (int)vtProp.intVal;

        hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
        auto _internal = std::wstring((wchar_t *)vtProp.bstrVal);
        auto wp = _internal.c_str();
        _bstr_t b(wp);
        const char* p = b;
        strcpy_s(i_result->cpu_name, 256 , p);//This part could be confusing
        //Since the BSTR type is defined as wchar_t* , which is mostly unnesseary,
        //the _bstr_t class is used to convert the wchar_t* to char* (const)
        //the copy the memory to the destination, which is i_result->cpu_name (a 
        //pointer to a construct-time alloced buffer.

        VariantClear(&vtProp);

        //Win32_OperatingSystem class is now queried.

        /*
        Win32_Processor
        NumberOfLogicalProcessors auto _internal = std::to_string((int)vtProp.intVal)
        LoadPercentage auto _internal = std::to_string((int)vtProp.intVal)
        Name
        */
        pclsObj->Release();
    }


    // Final Cleanups
    // ========

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();

    return 0;
}

void Pin_EnumSystemInfo(sysinfo_t* info_buf) {
    info_buf->cpu_bits = GetCPUBits();
    WMICALLER(info_buf, NULL);
    return;
}

static inline __int64 file_time_2_utc(const FILETIME* ftime){
    LARGE_INTEGER li;

    li.LowPart = ftime->dwLowDateTime;
    li.HighPart = ftime->dwHighDateTime;
    return li.QuadPart;
}

int get_cpu_usage(HANDLE hProcess){

    //number of cpus
    static int processor_count_ = -1;
    //last time
    static __int64 last_time_ = 0;
    static __int64 last_system_time_ = 0;

    FILETIME now;
    FILETIME creation_time;
    FILETIME exit_time;
    FILETIME kernel_time;
    FILETIME user_time;
    __int64 system_time;
    __int64 time;
    __int64 system_time_delta;
    __int64 time_delta;

    int cpu = -1;

    SYSTEM_INFO info;
    GetSystemInfo(&info);

    if (processor_count_ == -1)
    {
        processor_count_ = info.dwNumberOfProcessors;
    }

    GetSystemTimeAsFileTime(&now);

    system_time = (file_time_2_utc(&kernel_time) + file_time_2_utc(&user_time)) / processor_count_;
    time = file_time_2_utc(&now);

    if ((last_system_time_ == 0) || (last_time_ == 0))
    {
        last_system_time_ = system_time;
        last_time_ = time;
        return -1;
    }

    system_time_delta = system_time - last_system_time_;
    time_delta = time - last_time_;

    if (time_delta == 0)
        return -1;

    cpu = (int)((system_time_delta * 100 + time_delta / 2) / time_delta);
    last_system_time_ = system_time;
    last_time_ = time;
    return cpu;
}

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u/n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u/n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. /n");
        return FALSE;
    }

    return TRUE;
}

HANDLE GetProcessHandle(int nID)
{
    HANDLE hToken;
    bool flag = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
    if (!flag)
    {
        DWORD err = GetLastError();
        printf("OpenProcessToken error:%d", err);
    }
    SetPrivilege(hToken, SE_DEBUG_NAME, true);
    CloseHandle(hToken);
    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, nID);
}

class processinfo_t : public basic_pi_t {
public:
    virtual void AcquirePInformation() {

        TCHAR szProcessName[MAX_PATH] = TEXT("Not Enough Privilege");
        //this valued is used to represent process cant beopenned
        //by OpenProcess since the privileges might not enough.

        /*HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            FALSE, proc_id);*/
        HANDLE hProcess = GetProcessHandle(proc_id);

        //std::cout << hProcess <<" LastError " << GetLastError() << std::endl;

        if (NULL != hProcess) {
            PROCESS_MEMORY_COUNTERS ppsmemCounters;
            GetProcessMemoryInfo(hProcess, &ppsmemCounters, sizeof(ppsmemCounters));
            proc_mem = (ppsmemCounters.WorkingSetSize) >> 10;//in Kib
        }
        else {
            proc_mem = -1;
        }


        if (NULL != hProcess)
        {

            TCHAR Buffer[MAX_PATH];
            if (GetModuleBaseName(hProcess, 0, Buffer, MAX_PATH)){
                //std::wcout << "Path " << Buffer << std::endl;
                memset(szProcessName, 0, sizeof(WCHAR) * MAX_PATH);
                memcpy_s(szProcessName, sizeof(WCHAR) * MAX_PATH, Buffer , sizeof(WCHAR) * MAX_PATH);
            }
            else {
                //When debugging this function, this block is to call GetLastError

                //std::cout << "Error:" << GetLastError() << std::endl;
            }
        }

        auto _internal = std::wstring((wchar_t*)szProcessName);
        auto wp = _internal.c_str();
        _bstr_t b(wp);
        const char* p = b;
        strcpy_s(proc_name, sizeof(char) * MXLPN, p);

        if (hProcess == NULL) {
            get_cpu_usage(hProcess);
            /*
            Sleep(8);
            get_cpu_usage(hProcess);
            */
        }
        else {
            proc_cpu = -1;
        }

        if (hProcess != NULL) {
            CloseHandle(hProcess);
            //since the hProcess is NULL, there is no reson to close it.
        }
        return;
    }
};

int GetProcessList(p_pid_t* pid_lst) {
    /*
    If this funtion fails, the return val is -1,
    On a not likely occouring senario, return 0 is also wrong
    Or, the function return the number of process enumed instead.
    */

    DWORD cbNeeded, cProcesses;
    DWORD* aProcesses;
    aProcesses = (DWORD*)malloc(sizeof(DWORD) * MXPCS);

    if (aProcesses == NULL) {
        return -1;
    }
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses)*MXPCS, &cbNeeded))
    {
        return -1;
    }

    // Calculate how many process identifiers were returned.

    cProcesses = cbNeeded / sizeof(DWORD);

    // Print the name and process identifier for each process.

    for (i = 0; i < cProcesses; i++)
    {
        auto t = aProcesses[i];
        if (t != 0)
        {
            pid_lst[i] = aProcesses[i];
        }
    }

    free(aProcesses);
    //release the memory used

    return i;

}


int Pin_EnumProcessInfo(p_pid_t* pids, processinfo_t* info_t , const int process_count , int* process_now) {
    /*
    [in] process_count [out] process_count process_now
    When enumration fails, 0 will be returned.
    */
    if (process_count < (*process_now)) {
        return 0;
    }

    processinfo_t _info;
    _info.proc_id = pids[*process_now];
    _info.AcquirePInformation();
    
    info_t->proc_cpu = _info.proc_cpu;
    info_t->proc_id = _info.proc_id;
    info_t->proc_mem = _info.proc_mem;
    strcpy_s(info_t->proc_name, sizeof(char) * MXLPN, _info.proc_name);
    //copy every value from temporary mutable _info

    *(process_now) += 1;

    return 1;
}

#endif

void    Pin_EnumSystemInfo(sysinfo_t* info_buf);
int     Pin_EnumProcessInfo(p_pid_t* pids, processinfo_t* info_t, const int process_count, int* process_now);