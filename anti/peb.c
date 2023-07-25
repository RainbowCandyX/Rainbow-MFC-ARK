#include "peb.h"

ULONG_PTR Kthread_offset_ContextSwitches = 0;
ULONG_PTR Kthread_offset_state = 0;
ULONG_PTR Kthread_offset_Win32StartAddress = 0;
ULONG_PTR Kthread_offset_SuspendCount = 0;

ULONG_PTR enumObjectTableOffset_EPROCESS = 0;
ULONG_PTR eprocess_offset_VadHint = 0;
ULONG_PTR eprocess_offset_VadRoot = 0;
ULONG g_ObjectCallbackListOffset;

ULONG64 FindPattern(PVOID Start, ULONG64 Length, PCCH Pattern, PCCH Mask)
{
	PCCH Data = Start;
	size_t Pattern_length = strlen(Mask);
	for (INT i = 0; i <= Length - Pattern_length; i++)
	{
		BOOLEAN found = TRUE;
		for (size_t j = 0; j < Pattern_length; j++)
		{
			if (!MmIsAddressValid((Data + i + j)))
			{
				found = FALSE;
				break;
			}
			if (Data[i + j] != Pattern[j] && Mask[j] != '?')
			{
				found = FALSE;
				break;
			}
		}
		if (found)
		{
			return (Data + i);
		}
	}
	return NULL;
}

PVOID KGetKernelBase()
{
	ULONG64 PAGE = *(ULONG64*)(*((ULONG64*)KeGetPcr()->NtTib.SubSystemTib + 7) + 4) & 0xFFFFFFFFFFFFF000;
	for (; PAGE; PAGE -= PAGE_SIZE)
	{
		for (INT i = 0; i < PAGE_SIZE; i++)
		{
			ULONG64 Address = PAGE + i;
			if (*(UCHAR*)(Address) == 0x48 && *(UCHAR*)(Address + 1) == 0x8D && *(UCHAR*)(Address + 2) == 0x1D && *(UCHAR*)(Address + 6) == 0xFF)
			{
				INT Offset = *(INT*)(Address + 3);
				ULONG64 NTBase = Address + Offset + 7;
				if (!(NTBase & 0xFFF))
				{
					NTBase &= 0xFFFFFFFF00000000 | (UINT32)(PAGE + i + Offset + 7);
					return (PVOID)NTBase;
				}
			}
		}
	}
	return NULL;
}

ULONG KGetBuildNumber()
{
	RTL_OSVERSIONINFOW osi = { 0 };
	osi.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	RtlGetVersion(&osi);
	return osi.dwBuildNumber;
}

//支持系统
BOOLEAN initVerSion()
{
	ULONG Build = KGetBuildNumber();
	BOOLEAN bRet = FALSE;
	ULONG ThreadListEntry = 0, Win32StartAddress = 0;
	ULONG64 Address = FindPattern(KGetKernelBase(), 0x850000, "\x00\x8D\x00\x00\x00\x00\x00\x33\xD2\xE8\x00\x00\x00\x00\x48\x8B\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\x00\x3B", "?x?????xxx????xx????x???xx?x") + 0x16;
	if (MmIsAddressValid((PVOID)Address))
	{
		ThreadListEntry = *(ULONG*)Address;
		Win32StartAddress = ThreadListEntry - 0x18;
		if (Win32StartAddress >= 0x800) Win32StartAddress = 0;
	}

	if (Build >= 17134 && Build <= 19045)
	{
		Kthread_offset_ContextSwitches = 0x154;
		Kthread_offset_state = 0x184;
		Kthread_offset_Win32StartAddress = Win32StartAddress;//0x6A0
		Kthread_offset_SuspendCount = 0x284;
		enumObjectTableOffset_EPROCESS = *(ULONG*)((PUCHAR)PsGetProcessWow64Process + 3) - 0x10; /*句柄表偏移 位置*/
		eprocess_offset_VadRoot = *(ULONG*)((PUCHAR)PsGetProcessSignatureLevel + 15) - 0xA0;
		eprocess_offset_VadHint = eprocess_offset_VadRoot + 8;
		g_ObjectCallbackListOffset = 0xC8;
		bRet = TRUE;
	}
	if (Build >= 22000)
	{
		Kthread_offset_ContextSwitches = 0x154;
		Kthread_offset_state = 0x184;
		Kthread_offset_Win32StartAddress = Win32StartAddress;//_ETHREAD->Win32StartAddress
		Kthread_offset_SuspendCount = 0x284;//_KTHREAD->SuspendCount
		enumObjectTableOffset_EPROCESS = *(ULONG*)((PUCHAR)PsGetProcessWow64Process + 3) - 0x10;
		eprocess_offset_VadRoot = *(ULONG*)((PUCHAR)PsGetProcessSignatureLevel + 15) - 0xA0;//_EPROCESS->VadRoot
		eprocess_offset_VadHint = eprocess_offset_VadRoot + 8;//_EPROCESS->VadRoot + 8
		g_ObjectCallbackListOffset = 0xC8;
		bRet = TRUE;
	}

	return bRet;
}