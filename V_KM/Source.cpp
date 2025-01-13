#include <ntifs.h>
#include <ntddk.h>

const ULONG C_DMA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x591, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
const ULONG C_CLOSE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x592, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
const int v_key = 814957;

#define PageOffsetSize 12
static const UINT64 PageMask = (~0xfull << 8) & 0xfffffffffull;
//static const ULONG64 PageMask = 0x0000fffffffff000;

UNICODE_STRING NT_DEVICE_NAME, DOS_DEVICE_NAME;

NTSTATUS UnloadDriver(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);

struct Request {
	int t_key;
	INT32 t_PID;
	ULONGLONG VA;
	ULONGLONG BUFFER;
	ULONGLONG Size;
};

NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesRead) {
	MM_COPY_ADDRESS x = { 0 };
	x.PhysicalAddress.QuadPart = (LONGLONG)TargetAddress;
	return MmCopyMemory(Buffer, x, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

UINT64 ExGetCurrentUserDirectoryTableBase() {
	RTL_OSVERSIONINFOW VersionInfo = { 0 };
	RtlGetVersion(&VersionInfo);

	if (VersionInfo.dwMajorVersion == 10) {
		if (VersionInfo.dwMinorVersion == 0) {
			if (VersionInfo.dwBuildNumber >= 17134 && VersionInfo.dwBuildNumber <= 17763) {
				return 0x0278;
			}
			else if (VersionInfo.dwBuildNumber >= 18362 && VersionInfo.dwBuildNumber <= 18363) {
				return 0x0280;
			}
			else if (VersionInfo.dwBuildNumber >= 19041 && VersionInfo.dwBuildNumber <= 19043) {
				return 0x0388;
			}
		}
	}

	return 0x0388;
}

UINT64 ExGetProcessDataDirectoryTableBase(PEPROCESS Process) {
	if (!Process)
		return NULL;

	UINT64 DTB = *(uintptr_t*)((UINT8*)Process + 0x28);
	if (!DTB)
	{
		DTB = *(uintptr_t*)((UINT8*)Process + ExGetCurrentUserDirectoryTableBase());
	}

	if (!DTB)
		return 0;

	return DTB;
}

UINT64 TranslateLinearAddress(UINT64 DirectoryTableBase, UINT64 VirtualAddress) {
	DirectoryTableBase &= ~0xf;

	UINT64 PageOffset = VirtualAddress & ~(~0ul << PageOffsetSize);
	UINT64 PteIndex = ((VirtualAddress >> 12) & (0x1ffll));
	UINT64 PtIndex = ((VirtualAddress >> 21) & (0x1ffll));
	UINT64 PdIndex = ((VirtualAddress >> 30) & (0x1ffll));
	UINT64 PdpIndex = ((VirtualAddress >> 39) & (0x1ffll));

	SIZE_T ReadSize = 0;
	UINT64 PdpEntry = 0;


	ReadPhysicalAddress(PVOID(DirectoryTableBase + 8 * PdpIndex), &PdpEntry, sizeof(PdpEntry), &ReadSize);
	if (~PdpEntry & 1)
		return 0;



	UINT64 PdEntry = 0;
	ReadPhysicalAddress(PVOID((PdpEntry & PageMask) + 8 * PdIndex), &PdEntry, sizeof(PdEntry), &ReadSize);
	if (~PdEntry & 1)
		return 0;

	if (PdEntry & 0x80)
		return (PdEntry & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));


	UINT64 PtEntry = 0;
	ReadPhysicalAddress(PVOID((PdEntry & PageMask) + 8 * PtIndex), &PtEntry, sizeof(PtEntry), &ReadSize);
	if (~PtEntry & 1)
		return 0;


	if (PtEntry & 0x80)
		return (PtEntry & PageMask) + (VirtualAddress & ~(~0ull << 21));


	VirtualAddress = 0;
	ReadPhysicalAddress(PVOID((PtEntry & PageMask) + 8 * PteIndex), &VirtualAddress, sizeof(VirtualAddress), &ReadSize);
	VirtualAddress &= PageMask;

	if (!VirtualAddress)
		return 0;

	return VirtualAddress + PageOffset;
}

NTSTATUS ReadProcessMemory(int PID, ULONGLONG Address, ULONGLONG Buffer, SIZE_T Size)
{
	if (!PID || !Address || !Buffer || Size == 0)
		return STATUS_INVALID_PARAMETER;

	PEPROCESS Process;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)PID, &Process)))
		return STATUS_UNSUCCESSFUL;
	
	
	UINT64 DTB = ExGetProcessDataDirectoryTableBase(Process);
	ObDereferenceObject(Process);
	if (!DTB)
	
		return STATUS_UNSUCCESSFUL;
	

	UINT64 v_Address = TranslateLinearAddress(DTB, Address);
	if (!v_Address)
		return STATUS_UNSUCCESSFUL;
	
		

	ULONG64 v_Size = min((PAGE_SIZE - (v_Address & 0xFFF)), Size);
	SIZE_T read;

	PVOID bufferPointer = (PVOID)(ULONG64)Buffer;
	ReadPhysicalAddress((PVOID)v_Address, bufferPointer, v_Size, &read);
	return STATUS_SUCCESS;
}


NTSTATUS IrpHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	ULONG IoControlCode = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.IoControlCode;

	switch (IoControlCode)
	{
	case C_DMA:
	{ 
		auto vRequest = (Request*)Irp->AssociatedIrp.SystemBuffer;
		if (!(IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.InputBufferLength == sizeof(Request))) { break; }
		if ((vRequest->t_key != v_key)) { break; }
		ReadProcessMemory(vRequest->t_PID, vRequest->VA, vRequest->BUFFER, vRequest->Size);
		break;
	}
	
	case C_CLOSE:
	{
		UnloadDriver(DeviceObject, Irp);
		break;
	}
	

	default:
		break;
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}


NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
	switch (Stack->MajorFunction) {
	case IRP_MJ_CREATE:
	case IRP_MJ_CLOSE:
		break;
	default:
		break;
	}

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS UnloadDriver(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	IoDeleteSymbolicLink(&DOS_DEVICE_NAME);
	if (DeviceObject != NULL)
	{
		IoDeleteDevice(DeviceObject);
	}
	DbgPrint("[) Unloaded ");
	return STATUS_SUCCESS;
}

NTSTATUS V_Entry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
	PDEVICE_OBJECT deviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &NT_DEVICE_NAME, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
	if (!NT_SUCCESS(status))
		return status;

	status = IoCreateSymbolicLink(&DOS_DEVICE_NAME, &NT_DEVICE_NAME);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(deviceObject);
		return status;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;

	deviceObject->Flags |= DO_BUFFERED_IO;
	deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	DbgPrint("[) Loaded ");
	return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	RtlInitUnicodeString(&NT_DEVICE_NAME, L"\\Device\\green");
	RtlInitUnicodeString(&DOS_DEVICE_NAME, L"\\DosDevices\\green");
	return IoCreateDriver(NULL, V_Entry);
}