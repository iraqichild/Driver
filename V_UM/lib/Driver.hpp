@ -0,0 +1,176 @@
#include <windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include "nt.h"

typedef NTSTATUS(NTAPI* NtQuerySystemInformationPTR)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );


#define GENERIC_RW (GENERIC_READ | GENERIC_WRITE)
#define FILE_SHARE_RW (FILE_SHARE_READ | FILE_SHARE_WRITE)

const ULONG C_DMA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x591, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
const ULONG C_CLOSE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x592, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

class vDriver
{
private:
    HANDLE t_handle;
    int t_pid;
    const int t_key = 814957;



    struct Request {
        int t_key;
        INT32 t_PID;
        ULONGLONG VA;
        ULONGLONG BUFFER;
        ULONGLONG Size;
    };

public:
    bool OpenHandle()
    {
        this->t_handle = CreateFileW(L"\\\\.\\green", GENERIC_RW, FILE_SHARE_RW, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);
        if (this->t_handle == INVALID_HANDLE_VALUE)
            return false;

        return true;
    }
    bool CloseHandle()
    {
        if (!(::CloseHandle(this->t_handle)))
            return false;



        this->t_handle = NULL;

        return true;
    }
    bool UnloadDriver()
    {
        return DeviceIoControl(this->t_handle, C_CLOSE, 0, 0, 0, 0, 0, 0);
    }

    bool Attach(std::wstring ProcessName)
    {
        this->t_pid = this->GetProcessPid(ProcessName);
        if (!this->t_pid)
            return false;


        return true;
    }

    int GetProcessPid(std::wstring ProcessName)
    {
        NtQuerySystemInformationPTR NtQuery = (NtQuerySystemInformationPTR)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
        if (!NtQuery)
            return false;

        ULONG bufferSize = 1024 * 1024;
        std::unique_ptr<BYTE[]> buffer(new BYTE[bufferSize]);
        ULONG returnLength = 0;

        NTSTATUS status = NtQuery(SystemProcessInformation, buffer.get(), bufferSize, &returnLength);
        if (status != 0)
            return 0;

        SYSTEM_PROCESS_INFORMATION* processInfo = (SYSTEM_PROCESS_INFORMATION*)(buffer.get());
        while (processInfo) {
            std::wstring processNameStr(processInfo->ImageName.Buffer, processInfo->ImageName.Length / sizeof(wchar_t));

            if (processNameStr == ProcessName) {
                return (int)processInfo->UniqueProcessId;
            }

            if (processInfo->NextEntryOffset == 0)
                break;

            processInfo = (SYSTEM_PROCESS_INFORMATION*)(
                (BYTE*)(processInfo)+processInfo->NextEntryOffset);
        }
        return 0;
    }
    uint64_t GetKernelModuleBase(const char* ModuleName)
    {
        NtQuerySystemInformationPTR NtQuery = (NtQuerySystemInformationPTR)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
        if (!NtQuery)
            return 0;

        ULONG bufferSize = 1024 * 1024;
        std::unique_ptr<BYTE[]> buffer(new BYTE[bufferSize]);
        ULONG returnLength = 0;

        NTSTATUS status = NtQuery(SystemModuleInformation, buffer.get(), bufferSize, &returnLength);
        if (status != 0)
            return 0;

        RTL_PROCESS_MODULES* ModuleInfo = reinterpret_cast<RTL_PROCESS_MODULES*>(buffer.get());
        ULONG Size = ModuleInfo->NumberOfModules;

        for (ULONG i = 0; i < Size; i++)
        {
            std::string fullPath(reinterpret_cast<char*>(ModuleInfo->Modules[i].FullPathName));
            if (fullPath.find(ModuleName) != std::string::npos)
            {

                return (uintptr_t)ModuleInfo->Modules[i].ImageBase;
            }
        }

        return 0;
    }
    uint64_t GetModuleBaseAddress(std::wstring ModuleName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, this->t_pid);
        if (!hSnapshot)
            return 0;

        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(hSnapshot, &me32)) {
            do {
                if (ModuleName == me32.szModule) {
                    return (uint64_t)me32.modBaseAddr;
                    ::CloseHandle(hSnapshot);
                    return true;
                }
            } while (Module32Next(hSnapshot, &me32));
        }

        ::CloseHandle(hSnapshot);
        return NULL;
    }

    void ReadPhysicalMemory(PVOID Address, PVOID Buffer, SIZE_T BufferSize)
    {
        Request In = { };
        In.t_key = this->t_key;
        In.t_PID = this->t_pid;
        In.VA = (ULONGLONG)Address;
        In.BUFFER = (ULONGLONG)Buffer;
        In.Size = BufferSize;

        DeviceIoControl(this->t_handle, C_DMA, &In, sizeof(In), nullptr, 0, 0, 0);
    }

    template <typename BUF> BUF Read(uint64_t Address)
    {
        BUF TMP = { };
        this->ReadPhysicalMemory((PVOID)Address, &TMP, sizeof(BUF));
        return TMP;
    }
};



inline vDriver* Driver = new vDriver;
