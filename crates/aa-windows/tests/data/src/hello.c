/* Tiny fixture program. The imports exist only to give the import table something to classify. */
#include <winsock2.h>
#include <windows.h>

int main(int argc, char **argv) {
    (void)argv;
    if (argc > 100) {
        HKEY key;
        RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Fixture", 0, KEY_WRITE, &key);
        RegSetValueExA(key, "v", 0, REG_SZ, (const BYTE *)"x", 2);
        HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 4);
        void *remote = VirtualAllocEx(process, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(process, remote, "x", 1, NULL);
        CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        connect(s, NULL, 0);
        if (IsDebuggerPresent()) return 2;
    }
    return 0;
}
