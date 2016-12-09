// test.cpp : 以最低权限启动process。
//
#include "stdafx.h"
#include <windows.h>

BOOL IsUserAdmin(VOID)
/*++
Routine Description: This routine returns TRUE if the caller's
process is a member of the Administrators local group. Caller is NOT
expected to be impersonating anyone and is expected to be able to
open its own process and process token.
Arguments: None.
Return Value:
TRUE - Caller has Administrators local group.
FALSE - Caller does not have Administrators local group. --
*/
{
	BOOL b;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;
	b = AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdministratorsGroup);
	if (b)
	{
		if (!CheckTokenMembership(NULL, AdministratorsGroup, &b))
		{
			b = FALSE;
		}
		FreeSid(AdministratorsGroup);
	}

	return(b);
}


// 
//   FUNCTION: CreateLowIntegrityProcess(PCWSTR)
//
//   PURPOSE: The function launches an application at low integrity level. 
//
//   PARAMETERS:
//   * pszCommandLine - The command line to be executed. The maximum length 
//     of this string is 32K characters. This parameter cannot be a pointer 
//     to read-only memory (such as a const variable or a literal string). 
//     If this parameter is a constant string, the function may cause an 
//     access violation.
//
//   RETURN VALUE: If the function succeeds, the return value is TRUE. If the 
//   function fails, the return value is zero. To get extended error 
//   information, call GetLastError.
//
//   COMMENT:
//   To start a low-integrity process, 
//   1) Duplicate the handle of the current process, which is at medium 
//      integrity level.
//   2) Use SetTokenInformation to set the integrity level in the access 
//      token to Low.
//   3) Use CreateProcessAsUser to create a new process using the handle to 
//      the low integrity access token.
//
BOOL CreateLowIntegrityProcess(PTSTR pszCommandLine)
{
	DWORD dwError = ERROR_SUCCESS;
	HANDLE hToken = NULL;
	HANDLE hNewToken = NULL;
	SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
	PSID pIntegritySid = NULL;
	TOKEN_MANDATORY_LABEL tml = { 0 };
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };

	// Open the primary access token of the process.
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY |
		TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY, &hToken))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Duplicate the primary token of the current process.
	if (!DuplicateTokenEx(hToken, 0, NULL, SecurityImpersonation,
		TokenPrimary, &hNewToken))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Create the low integrity SID.
	//通过变更SECURITY_MANDATORY_LOW_RID，可以以不同的权限启动进程
	if (!AllocateAndInitializeSid(&MLAuthority, 1, SECURITY_MANDATORY_LOW_RID,
		0, 0, 0, 0, 0, 0, 0, &pIntegritySid))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	tml.Label.Attributes = SE_GROUP_INTEGRITY;
	tml.Label.Sid = pIntegritySid;

	// Set the integrity level in the access token to low.
	if (!SetTokenInformation(hNewToken, TokenIntegrityLevel, &tml,
		(sizeof(tml) + GetLengthSid(pIntegritySid))))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Create the new process at the Low integrity level.
	//pszCommandLine: exePath + parameter.eg:xx.exe --begin(可执行文件的全路径与参数间使用空格分开)
	if (!CreateProcessAsUser(hNewToken, NULL, pszCommandLine, NULL, NULL,
		FALSE, 0, NULL, NULL, &si, &pi))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (hToken)
	{
		CloseHandle(hToken);
		hToken = NULL;
	}
	if (hNewToken)
	{
		CloseHandle(hNewToken);
		hNewToken = NULL;
	}
	if (pIntegritySid)
	{
		FreeSid(pIntegritySid);
		pIntegritySid = NULL;
	}
	if (pi.hProcess)
	{
		CloseHandle(pi.hProcess);
		pi.hProcess = NULL;
	}
	if (pi.hThread)
	{
		CloseHandle(pi.hThread);
		pi.hThread = NULL;
	}

	if (ERROR_SUCCESS != dwError)
	{
		// Make sure that the error code is set for failure.
		SetLastError(dwError);
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

int _tmain(int argc, _TCHAR* argv[])
{

	if (IsUserAdmin())
	{
		CreateLowIntegrityProcess(TEXT("C:\\Windows\\System32\\notepad.exe"));
	}
	
	return 0;
}


