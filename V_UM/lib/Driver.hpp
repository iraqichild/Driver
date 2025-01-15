#include <windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <chrono>
#include <thread>
#include "nt.h"

typedef NTSTATUS(NTAPI* NtQuerySystemInformationPTR)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* NtDeviceIoControlFilePTR)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength
    );

typedef NTSTATUS(NTAPI* NtQueryInformationProcessPTR)(
        _In_ HANDLE ProcessHandle,
        _In_ PROCESSINFOCLASS ProcessInformationClass,
        _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
        _In_ ULONG ProcessInformationLength,
        _Out_opt_ PULONG ReturnLength
    );

#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)

#define GENERIC_RW (GENERIC_READ | GENERIC_WRITE)
#define FILE_SHARE_RW (FILE_SHARE_READ | FILE_SHARE_WRITE)

const ULONG C_DMA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x591, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
const ULONG C_CLOSE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x592, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

inline class cDriver
{
private:
    HANDLE t_handle;
    int t_pid;
    const int t_key = 814957;

    NtQuerySystemInformationPTR NtQuerySystemInformation;
    NtDeviceIoControlFilePTR NtDeviceIoControlFile;
    NtQueryInformationProcessPTR NtQueryInformationProcess;

    struct Request {
        int t_key;
        INT32 t_PID;
        ULONGLONG VA;
        ULONGLONG BUFFER;
        ULONGLONG Size;
        enum e_DMA_TYPE
        {
            read,
            write
        } DMA_TYPE;
    };


    std::chrono::steady_clock::time_point lastReadTime;
    const std::chrono::microseconds readRateLimit = std::chrono::microseconds(1); 

public:
    void InitNtdll()
    {
        HMODULE ntdll = GetModuleHandle(TEXT("ntdll.dll"));
        if (ntdll)
        {
            NtQuerySystemInformation = (NtQuerySystemInformationPTR)GetProcAddress(ntdll, "NtQuerySystemInformation");
            NtDeviceIoControlFile = (NtDeviceIoControlFilePTR)GetProcAddress(ntdll, "NtDeviceIoControlFile");
            NtQueryInformationProcess = (NtQueryInformationProcessPTR)GetProcAddress(ntdll, "NtQueryInformationProcess");
        }

    }

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

    bool DeviceIoControl(_In_ HANDLE hDevice,
        _In_ DWORD dwIoControlCode,
        _In_reads_bytes_opt_(nInBufferSize) LPVOID lpInBuffer,
        _In_ DWORD nInBufferSize,
        _Out_writes_bytes_to_opt_(nOutBufferSize, *lpBytesReturned) LPVOID lpOutBuffer,
        _In_ DWORD nOutBufferSize,
        _Out_opt_ LPDWORD lpBytesReturned,
        _Inout_opt_ LPOVERLAPPED lpOverlapped)

    {
        IO_STATUS_BLOCK IoStatusBlock = { };

        NtDeviceIoControlFile(
            this->t_handle,
            NULL,
            NULL,
            NULL,
            &IoStatusBlock,
            dwIoControlCode,
            lpInBuffer,
            nInBufferSize,
            0,
            0
        );

        if (IoStatusBlock.Status == STATUS_SUCCESS) {
            return true;
        }
        else {
            return false;
        }
    }

    bool UnloadDriver()
    {
        return this->DeviceIoControl(this->t_handle, C_CLOSE, 0, 0, 0, 0, 0, 0);
    }

    bool Attach(std::wstring ProcessName)
    {
        this->InitNtdll();

        if (!(this->OpenHandle()))
            return false;

        this->t_pid = this->GetProcessPid(ProcessName);
        if (!this->t_pid)
            return false;

        return true;
    }

    int GetProcessPid(std::wstring ProcessName)
    {
        ULONG bufferSize = 1024 * 1024;
        std::unique_ptr<BYTE[]> buffer(new BYTE[bufferSize]);
        ULONG returnLength = 0;

        NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, buffer.get(), bufferSize, &returnLength);
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

    uintptr_t GetProcessPEBAddress()
    {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, this->t_pid);
        if (!hProcess)
            return 0;

        PROCESS_BASIC_INFORMATION pbi;
        ULONG len = 0;
        NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len);

        ::CloseHandle(hProcess);

        return (uintptr_t)pbi.PebBaseAddress;
    }


    uint64_t GetKernelModuleBase(const char* ModuleName)
    {

        ULONG bufferSize = 1024 * 1024;
        std::unique_ptr<BYTE[]> buffer(new BYTE[bufferSize]);
        ULONG returnLength = 0;

        NTSTATUS status = this->NtQuerySystemInformation(SystemModuleInformation, buffer.get(), bufferSize, &returnLength);
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
        // prvent the bsods lmao
       // auto now = std::chrono::steady_clock::now();
       // if (now - lastReadTime < readRateLimit) {
       //     std::this_thread::sleep_for(readRateLimit - (now - lastReadTime));
       // }

        Request In = { };
        In.t_key = this->t_key;
        In.t_PID = this->t_pid;
        In.VA = (ULONGLONG)Address;
        In.BUFFER = (ULONGLONG)Buffer;
        In.Size = BufferSize;
        In.DMA_TYPE = In.read;

        this->DeviceIoControl(this->t_handle, C_DMA, &In, sizeof(In), nullptr, 0, 0, 0);

        //lastReadTime = std::chrono::steady_clock::now();
    }

    void WritePhysicalMemory(PVOID Address, PVOID Buffer, SIZE_T BufferSize)
    {
        Request In = { };
        In.t_key = this->t_key;
        In.t_PID = this->t_pid;
        In.VA = (ULONGLONG)Address;
        In.BUFFER = (ULONGLONG)Buffer;
        In.Size = BufferSize;
        In.DMA_TYPE = In.write;

        this->DeviceIoControl(this->t_handle, C_DMA, &In, sizeof(In), nullptr, 0, 0, 0);
    }

    template <typename BUF> BUF Read(uint64_t Address)
    {
        BUF TMP = { };
        this->ReadPhysicalMemory((PVOID)Address, &TMP, sizeof(BUF));
        return TMP;
    }

    template <typename T>
    T Write(uint64_t address, T buffer) {

        WritePhysicalMemory((PVOID)address, &buffer, sizeof(T));
        return buffer;
    }

} Driver;
