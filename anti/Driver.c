#include "heads.h"
#include "emunKernelModule.h"
#include "CommFunction.h"
#include "KernelInject.h"
#include "emunAllKernleCallBack.h"
BOOLEAN g_bInit = FALSE;
BOOLEAN g_bInitPte = FALSE;
_NtSuspendThread NtSuspendThread = NULL;
_NtResumeThread  NtResumeThread = NULL;
_NtTerminateThread NtTerminateThread = NULL;
_ZwCreateThreadEx ZwCreateThreadEx = NULL;
pfnNtAlertResumeThread NtAlertResumeThread = NULL;
pfnNtQueueApcThread NtQueueApcThread = NULL;

ZWPROTECTVIRTUALMEMORY pfnZwProtectVirtualMemory = NULL;
ZWREADVIRTUALMEMORY pfnZwReadVirtualMemory = NULL;
ZWWRITEVIRTUALMEMORY pfnZwWriteVirtualMemory = NULL;
ULONG64 g_PspLoadImageNotifyRoutine = NULL;
ULONG64 g_PspCreateThreadNotifyRoutine = NULL;
ULONG64 g_CmCallbackListHead = NULL;
ULONG64 g_PspCreateProcessNotifyRoutine = NULL;

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	if (g_bInit) {
		UNICODE_STRING symLinkName;
		RtlInitUnicodeString(&symLinkName, ·ûºÅÃû);
		IoDeleteSymbolicLink(&symLinkName);
		IoDeleteDevice(pDriverObject->DeviceObject);

		Deinitialize();
	}

	if (g_InitLoadImage) {
		PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);
	}

	if (g_pInjectInfo)
	{
		
		RtlFreeMemory(g_pInjectInfo);
		g_pInjectInfo = NULL;
	}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryString)
{
	UNREFERENCED_PARAMETER(pRegistryString);
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	pDriverObject->DriverUnload = DriverUnload;

	if (!initVerSion()) 
	{
		return STATUS_UNSUCCESSFUL;
	}
	
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &DispatchControlCode;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = &test_DispatchControlCode;
	status = CreateDevice(pDriverObject);

	if (NT_SUCCESS(Initialize()))
	{
		 pfnZwProtectVirtualMemory = GetKernelZwFuncByName("ZwProtectVirtualMemory");
		 ZwCreateThreadEx = GetKernelZwFuncByName("ZwCreateThreadEx");

		 pfnZwReadVirtualMemory = GetKernelZwFuncByName("ZwReadVirtualMemory");
		 pfnZwWriteVirtualMemory = GetKernelZwFuncByName("ZwWriteVirtualMemory");

		 if (pfnZwProtectVirtualMemory && ZwCreateThreadEx &&pfnZwReadVirtualMemory&&pfnZwWriteVirtualMemory) {
			 g_bInit = TRUE;
		 }
	}

	if (InitializePteBase())
	{
		g_bInitPte = TRUE;
	}	
	return status;
}


