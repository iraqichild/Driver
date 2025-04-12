<<<<<<< HEAD
#include <Windows.h>
#include <string>
#include <iostream>

#define IOCTL_DMA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x591, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_CLOSE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x593, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

enum class REQUEST_TYPE {
    READVA,
    WRITEVA,
    READPA,
    WRITEPA,
    ATTACH,
    DETACH,
    MODULE,
    CR3
};

struct REQUEST {
    UINT64 UniqueProcessId;
    UINT64 DirectoryTableBase;
    void* pPeprocess;
    void* VirtualAddress;
    void* BufferAddress;
    SIZE_T BufferSize;
    REQUEST_TYPE TYPE;
};

class cMemory {
public:
    HANDLE hDevice;
    REQUEST req;

    bool Open() {
        hDevice = CreateFile(L"\\\\.\\sss", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        return hDevice != INVALID_HANDLE_VALUE;
    }

    void Close() {
        CloseHandle(hDevice);
    }

    bool Attach(const std::string& processName) {
        DWORD pid = 1234;
        req.UniqueProcessId = pid;
        req.TYPE = REQUEST_TYPE::ATTACH;
        return DeviceIoControl(hDevice, IOCTL_DMA, &req, sizeof(req), &req, sizeof(req), NULL, NULL);
    }

    void* GetModuleBase(const std::string& moduleName) {
        WCHAR wModuleName[256];
        MultiByteToWideChar(CP_ACP, 0, moduleName.c_str(), -1, wModuleName, 256);
        req.BufferAddress = wModuleName;
        req.TYPE = REQUEST_TYPE::MODULE;
        if (DeviceIoControl(hDevice, IOCTL_DMA, &req, sizeof(req), &req, sizeof(req), NULL, NULL)) {
            return req.VirtualAddress;
        }
        return nullptr;
    }

    UINT64 GetDtb() {
        req.TYPE = REQUEST_TYPE::CR3;
        if (DeviceIoControl(hDevice, IOCTL_DMA, &req, sizeof(req), &req, sizeof(req), NULL, NULL)) {
            return req.DirectoryTableBase;
        }
        return 0;
    }

    template <typename T>
    T Read(uintptr_t address) {
        T value = {};
        req.VirtualAddress = (void*)address;
        req.BufferAddress = &value;
        req.BufferSize = sizeof(T);
        req.TYPE = REQUEST_TYPE::READVA;
        if (DeviceIoControl(hDevice, IOCTL_DMA, &req, sizeof(req), &req, sizeof(req), NULL, NULL)) {
            return value;
        }
        return T{};
    }

    template <typename T>
    bool Write(uintptr_t address, const T& value) {
        req.VirtualAddress = (void*)address;
        req.BufferAddress = (void*)&value;
        req.BufferSize = sizeof(T);
        req.TYPE = REQUEST_TYPE::WRITEVA;
        return DeviceIoControl(hDevice, IOCTL_DMA, &req, sizeof(req), &req, sizeof(req), NULL, NULL);
    }

    bool Detach() {
        req.TYPE = REQUEST_TYPE::DETACH;
        return DeviceIoControl(hDevice, IOCTL_DMA, &req, sizeof(req), &req, sizeof(req), NULL, NULL);
    }
};
=======
#include <windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
>>>>>>> parent of b3be6c2 (dohickys)


int main()
{
<<<<<<< HEAD
    cMemory Memory;
    if (!Memory.Open())
        return -1;

    if (!Memory.Attach("cs2.exe"))
    {
        Memory.Close();
        return -1;
    }

    uintptr_t clientdll = (uintptr_t)Memory.GetModuleBase("client.dll");

    std::cout << clientdll << "\n";

    uintptr_t pawn = Memory.Read<uintptr_t>(clientdll + 0x188BF30);
       
    int health = Memory.Read<int>((pawn + 0x344));

    std::cout << health;

    Memory.Detach();
    Memory.Close();

=======
  
>>>>>>> parent of b3be6c2 (dohickys)
    return 0;
}