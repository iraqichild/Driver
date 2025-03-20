#include <ntifs.h>
#include <ntddk.h>

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    unsigned short LoadCount;
    unsigned short TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA LoaderData;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID FastPebLockRoutine;
    PVOID FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID KernelCallbackTable;
    PVOID EventLogSection;
    PVOID EventLog;
    PVOID FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[0x2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    unsigned char Spare2[0x4];
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID** ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    PVOID GdiDCAttributeList;
    PVOID LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    ULONG OSBuildNumber;
    ULONG OSPlatformId;
    ULONG ImageSubSystem;
    ULONG ImageSubSystemMajorVersion;
    ULONG ImageSubSystemMinorVersion;
    ULONG GdiHandleBuffer[0x22];
    ULONG PostProcessInitRoutine;
    ULONG TlsExpansionBitmap;
    unsigned char TlsExpansionBitmapBits[0x80];
    ULONG SessionId;
} PEB, * PPEB;

NTSTATUS UnloadDriver(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesRead);
NTSTATUS WritePhysicalAddress(PVOID TargetAddress, PVOID Buffer, SIZE_T Size);
UINT64 TranslateLinearAddress(UINT64 DirectoryTableBase, UINT64 VirtualAddress);
NTSTATUS IrpControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
NTSTATUS DispatchHandler(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
NTSTATUS UnloadDriver(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
NTSTATUS FxDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath);
EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
EXTERN_C NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);

typedef struct _REQUEST {
    UINT64 UniqueProcessId;
    UINT64 DirectoryTableBase;
    void* pPeprocess;
    void* VirtualAddress;
    void* BufferAddress;
    SIZE_T BufferSize;
    enum _TYPE
    {
        READVA,
        WRITEVA,
        READPA,
        WRITEPA,
        ATTACH,
        DETACH,
        MODULE,
        CR3
    } TYPE;
} REQUEST, * PREQUEST;

namespace KGLOBAL
{
    UNICODE_STRING NT_DEVICE_NAME, DOS_DEVICE_NAME;
    const ULONG C_DMA = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x591, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    const ULONG C_CLOSE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x593, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
}

namespace KAttached
{
    PEPROCESS pPeprocess = nullptr;
    UINT64 UniqueProcessId = 0;
    UINT64 DirectoryTableBase = 0;
    BOOLEAN IsAttached = false;

    NTSTATUS AttachProcess(UINT64 uniqueProcessId)
    {
        NTSTATUS status = STATUS_SUCCESS;
        PEPROCESS Process = nullptr;

        status = PsLookupProcessByProcessId((HANDLE)uniqueProcessId, &Process);
        if (!NT_SUCCESS(status))
        {
            IsAttached = false;
            return status;
        }

        pPeprocess = Process;
        UniqueProcessId = uniqueProcessId;
        DirectoryTableBase = *(PUINT64)((PUCHAR)Process + 0x28);
        if (!DirectoryTableBase || (DirectoryTableBase >> 0x38) == 0x40)
        {
            ObDereferenceObject(Process);
            pPeprocess = nullptr;
            UniqueProcessId = 0;
            DirectoryTableBase = 0;
            IsAttached = false;
            return STATUS_UNSUCCESSFUL;
        }

        ObDereferenceObject(Process);
        IsAttached = true;
        return STATUS_SUCCESS;
    }

    NTSTATUS DetachProcess()
    {
        if (!pPeprocess)
        {
            IsAttached = false;
            return STATUS_NOT_FOUND;
        }

        pPeprocess = nullptr;
        UniqueProcessId = 0;
        DirectoryTableBase = 0;
        IsAttached = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS CR3()
    {
        if (!IsAttached || !pPeprocess)
            return STATUS_UNSUCCESSFUL;

        DirectoryTableBase = *(PUINT64)((PUCHAR)pPeprocess + 0x28);
        if (!DirectoryTableBase || (DirectoryTableBase >> 0x38) == 0x40)
        {
            pPeprocess = nullptr;
            UniqueProcessId = 0;
            DirectoryTableBase = 0;
            IsAttached = false;
            return STATUS_UNSUCCESSFUL;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS GetModuleBase(const WCHAR ModuleName[256], PVOID* ModuleBase)
    {
        NTSTATUS status = STATUS_SUCCESS;
        KAPC_STATE apcState = { 0 };
        BOOLEAN attached = FALSE;

        if (!ModuleBase || !ModuleName || !ModuleName[0])
            return STATUS_INVALID_PARAMETER;

        *ModuleBase = nullptr;

        if (!IsAttached || !pPeprocess)
            return STATUS_NOT_FOUND;

        __try
        {
            KeStackAttachProcess(pPeprocess, &apcState);
            attached = TRUE;

            PPEB peb = PsGetProcessPeb(pPeprocess);
            if (!peb || !peb->LoaderData)
            {
                status = STATUS_UNSUCCESSFUL;
                goto Cleanup;
            }

            PPEB_LDR_DATA ldrData = peb->LoaderData;
            PLIST_ENTRY moduleListHead = &ldrData->InMemoryOrderModuleList;
            PLIST_ENTRY currentEntry = moduleListHead->Flink;

            while (currentEntry != moduleListHead)
            {
                PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(currentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                if (!ldrEntry->BaseDllName.Buffer || ldrEntry->BaseDllName.Length == 0)
                {
                    currentEntry = currentEntry->Flink;
                    continue;
                }

                if (_wcsicmp(ldrEntry->BaseDllName.Buffer, ModuleName) == 0)
                {
                    *ModuleBase = ldrEntry->DllBase;
                    status = STATUS_SUCCESS;
                    goto Cleanup;
                }
                currentEntry = currentEntry->Flink;
            }

            status = STATUS_NOT_FOUND;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = STATUS_UNHANDLED_EXCEPTION;
        }

    Cleanup:
        if (attached)
            KeUnstackDetachProcess(&apcState);
        return status;
    }

    NTSTATUS ReadVirtualAddress(PVOID VirtualAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesRead)
    {
        if (!IsAttached || !VirtualAddress || !Buffer || Size == 0)
            return STATUS_INVALID_PARAMETER;

        UINT64 physicalAddress = TranslateLinearAddress(DirectoryTableBase, (UINT64)VirtualAddress);
        if (!physicalAddress)
            return STATUS_UNSUCCESSFUL;

        return ReadPhysicalAddress((PVOID)physicalAddress, Buffer, min(PAGE_SIZE - (physicalAddress & 0xFFF), Size), BytesRead);
    }

    NTSTATUS WriteVirtualAddress(PVOID VirtualAddress, PVOID Buffer, SIZE_T Size)
    {
        if (!IsAttached || !VirtualAddress || !Buffer || Size == 0)
            return STATUS_INVALID_PARAMETER;

        UINT64 physicalAddress = TranslateLinearAddress(DirectoryTableBase, (UINT64)VirtualAddress);
        if (!physicalAddress)
            return STATUS_UNSUCCESSFUL;

        return WritePhysicalAddress((PVOID)physicalAddress, Buffer, min(PAGE_SIZE - (physicalAddress & 0xFFF), Size));
    }
}

NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesRead) {
    MM_COPY_ADDRESS x = { 0 };
    x.PhysicalAddress.QuadPart = (LONGLONG)TargetAddress;
    return MmCopyMemory(Buffer, x, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

NTSTATUS WritePhysicalAddress(PVOID TargetAddress, PVOID Buffer, SIZE_T Size)
{
    PHYSICAL_ADDRESS x = { 0 };
    x.QuadPart = LONGLONG(TargetAddress);
    PVOID pmapped_mem = MmMapIoSpaceEx(x, Size, PAGE_READWRITE);
    if (!pmapped_mem)
        return STATUS_UNSUCCESSFUL;
    memcpy(pmapped_mem, Buffer, Size);
    MmUnmapIoSpace(pmapped_mem, Size);
    return STATUS_SUCCESS;
}

UINT64 TranslateLinearAddress(UINT64 DirectoryTableBase, UINT64 VirtualAddress) {
    const UINT64 PAGE_MASK = (~0xfull << 8) & 0xfffffffffull;
    DirectoryTableBase &= ~0xf;
    UINT64 pageOffset = VirtualAddress & ~(~0ull << PAGE_SHIFT);
    UINT64 pteIndex = (VirtualAddress >> 12) & 0x1ff;
    UINT64 ptIndex = (VirtualAddress >> 21) & 0x1ff;
    UINT64 pdIndex = (VirtualAddress >> 30) & 0x1ff;
    UINT64 pdpIndex = (VirtualAddress >> 39) & 0x1ff;

    SIZE_T bytesRead;
    UINT64 pdpEntry, pdEntry, ptEntry, result;

    if (!NT_SUCCESS(ReadPhysicalAddress((PVOID)(DirectoryTableBase + 8 * pdpIndex), &pdpEntry, sizeof(pdpEntry), &bytesRead)))
        return 0;
    if (!(pdpEntry & 1))
        return 0;
    if (!NT_SUCCESS(ReadPhysicalAddress((PVOID)((pdpEntry & PAGE_MASK) + 8 * pdIndex), &pdEntry, sizeof(pdEntry), &bytesRead)))
        return 0;
    if (!(pdEntry & 1))
        return 0;
    if (pdEntry & 0x80)
        return (pdEntry & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));
    if (!NT_SUCCESS(ReadPhysicalAddress((PVOID)((pdEntry & PAGE_MASK) + 8 * ptIndex), &ptEntry, sizeof(ptEntry), &bytesRead)))
        return 0;
    if (!(ptEntry & 1))
        return 0;
    if (ptEntry & 0x80)
        return (ptEntry & PAGE_MASK) + (VirtualAddress & ~(~0ull << 21));
    if (!NT_SUCCESS(ReadPhysicalAddress((PVOID)((ptEntry & PAGE_MASK) + 8 * pteIndex), &result, sizeof(result), &bytesRead)))
        return 0;
    return (result & PAGE_MASK) + pageOffset;
}

NTSTATUS IrpControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);
    ULONG IoControlCode = IoGetCurrentIrpStackLocation(pIrp)->Parameters.DeviceIoControl.IoControlCode;
    PREQUEST pRequest = (PREQUEST)pIrp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T bytesTransferred = 0;

    if (!pRequest || sizeof(REQUEST) != IoGetCurrentIrpStackLocation(pIrp)->Parameters.DeviceIoControl.InputBufferLength)
    {
        pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        pIrp->IoStatus.Information = 0;
        IofCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }

    switch (IoControlCode)
    {
    case KGLOBAL::C_DMA:
        switch (pRequest->TYPE)
        {
        case REQUEST::_TYPE::ATTACH:
            status = KAttached::AttachProcess(pRequest->UniqueProcessId);
            if (NT_SUCCESS(status))
            {
                pRequest->pPeprocess = KAttached::pPeprocess;
                pRequest->UniqueProcessId = KAttached::UniqueProcessId;
                pRequest->DirectoryTableBase = KAttached::DirectoryTableBase;
                bytesTransferred = sizeof(REQUEST);
            }
            else
            {
                bytesTransferred = 0;
            }
            break;

        case REQUEST::_TYPE::DETACH:
            status = KAttached::DetachProcess();
            bytesTransferred = 0;
            break;

        case REQUEST::_TYPE::CR3:
            status = KAttached::CR3();
            if (NT_SUCCESS(status))
            {
                pRequest->DirectoryTableBase = KAttached::DirectoryTableBase;
                bytesTransferred = sizeof(UINT64);
            }
            else
            {
                bytesTransferred = 0;
            }
            break;

        case REQUEST::_TYPE::MODULE:
            status = KAttached::GetModuleBase((const WCHAR*)pRequest->BufferAddress, (PVOID*)&pRequest->VirtualAddress);
            if (NT_SUCCESS(status))
            {
                bytesTransferred = sizeof(PVOID);
            }
            else
            {
                bytesTransferred = 0;
            }
            break;

        case REQUEST::_TYPE::READPA:
            status = ReadPhysicalAddress(pRequest->VirtualAddress, pRequest->BufferAddress, pRequest->BufferSize, &pRequest->BufferSize);
            bytesTransferred = pRequest->BufferSize;
            break;

        case REQUEST::_TYPE::WRITEPA:
            status = WritePhysicalAddress(pRequest->VirtualAddress, pRequest->BufferAddress, pRequest->BufferSize);
            bytesTransferred = 0;
            break;

        case REQUEST::_TYPE::READVA:
            status = KAttached::ReadVirtualAddress(pRequest->VirtualAddress, pRequest->BufferAddress, pRequest->BufferSize, &pRequest->BufferSize);
            bytesTransferred = pRequest->BufferSize;
            break;

        case REQUEST::_TYPE::WRITEVA:
            status = KAttached::WriteVirtualAddress(pRequest->VirtualAddress, pRequest->BufferAddress, pRequest->BufferSize);
            bytesTransferred = 0;
            break;

        default:
            status = STATUS_NOT_SUPPORTED;
            bytesTransferred = 0;
            break;
        }
        break;

    case KGLOBAL::C_CLOSE:
        status = UnloadDriver(pDeviceObject, pIrp);
        bytesTransferred = 0;
        break;

    default:
        status = STATUS_NOT_SUPPORTED;
        bytesTransferred = 0;
        break;
    }

    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = bytesTransferred;
    IofCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DispatchHandler(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(pIrp);
    switch (Stack->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        break;
    case IRP_MJ_DEVICE_CONTROL:
        IrpControl(pDeviceObject, pIrp);
        break;
    default:
        break;
    }
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS UnloadDriver(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    IoDeleteSymbolicLink(&KGLOBAL::DOS_DEVICE_NAME);
    if (pDeviceObject != NULL)
    {
        IoDeleteDevice(pDeviceObject);
    }
    DbgPrint("[) Unloaded ");
    return STATUS_SUCCESS;
}

NTSTATUS FxDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
    PDEVICE_OBJECT deviceObject;
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &KGLOBAL::NT_DEVICE_NAME, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (!NT_SUCCESS(status))
        return status;

    status = IoCreateSymbolicLink(&KGLOBAL::DOS_DEVICE_NAME, &KGLOBAL::NT_DEVICE_NAME);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchHandler;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchHandler;

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[) Loaded");
    return STATUS_SUCCESS;
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    if (!DriverObject)
    {
        RtlInitUnicodeString(&KGLOBAL::NT_DEVICE_NAME, L"\\Device\\sss");
        RtlInitUnicodeString(&KGLOBAL::DOS_DEVICE_NAME, L"\\DosDevices\\sss");

        UNICODE_STRING IoCreateDriverName;
        RtlInitUnicodeString(&IoCreateDriverName, L"IoCreateDriver");

        typedef NTSTATUS(*IoCreateDriver_t)(PUNICODE_STRING, PDRIVER_INITIALIZE);
        IoCreateDriver_t IoCreateDriverPtr = (IoCreateDriver_t)MmGetSystemRoutineAddress(&IoCreateDriverName);

        if (!IoCreateDriverPtr)
            return STATUS_PROCEDURE_NOT_FOUND;

        return IoCreateDriverPtr(NULL, FxDriverEntry);
    }
    return STATUS_SUCCESS;
}
