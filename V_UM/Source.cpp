#include "lib/Driver.hpp"
#include <chrono>
#include <iostream>
#include <vector>

int main()
{
    if (!Driver.Attach(L"RobloxPlayerBeta.exe"))
        printf("fail");


    uintptr_t PebAddress = Driver.GetProcessPEBAddress();
    ULONG ImageSystem;
    Driver.ReadPhysicalMemory((PVOID)(PebAddress + 0x128), &ImageSystem, sizeof(ULONG));
   
    printf("[) _PEB->ImageSystem = %d\n", ImageSystem);
   
    ULONG buf = 50;

    Driver.Write<ULONG>(PebAddress + 0x128, buf);


    Driver.ReadPhysicalMemory((PVOID)(PebAddress + 0x128), &ImageSystem, sizeof(ULONG));

    printf("[) _PEB->ImageSystem = %d\n", ImageSystem);

    Driver.CloseHandle();
    return 0;
}
