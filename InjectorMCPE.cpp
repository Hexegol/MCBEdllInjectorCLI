#include <iostream>
#include <windows.h>    // Pour les API Windows
#include <tlhelp32.h>   // Pour les fonctions de snapshot des processus
#include <string>       // Pour std::string

DWORD FindProcessId(const char* processName) {
    DWORD processId = 0;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hProcessSnap, &pe32)) {
            do {
                if (strcmp(pe32.szExeFile, processName) == 0) {
                    processId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hProcessSnap, &pe32));
        }
        CloseHandle(hProcessSnap);
    }
    return processId;
}

int main() {
    const char* processName = "Minecraft.Windows.exe";
    DWORD processID = FindProcessId(processName);

    if (processID == 0) {
        std::cout << "process not found" << std::endl;
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si); 
        ZeroMemory(&pi, sizeof(pi)); 
        const char* minecraftPath = "C:\\Program Files\\WindowsApps\\Microsoft.MinecraftUWP_1.21.2201.0_x64__8wekyb3d8bbwe\\Minecraft.Windows.exe";

        if (!CreateProcess(
            NULL,                   
            (LPSTR)minecraftPath,   
            NULL,                  
            NULL,                   
            FALSE,                  
            0,                      
            NULL,                  
            NULL,                
            &si,                   
            &pi)                    
            ) {
            std::cerr << "CreateProcess failed" << GetLastError() << std::endl;
        }

        std::cout << "minecraft started" << std::endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (processHandle == NULL) {
        std::cout << "unable to open the process" << std::endl;
        return 1;
    }

    VirtualAllocEx(processHandle, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    std::string dllPath;
    std::cout << "enter the path of the dll to inject : ";
    std::cin >> dllPath;
    LPVOID dllPathAddress = VirtualAllocEx(processHandle, NULL, dllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(processHandle, dllPathAddress, dllPath.c_str(), dllPath.size() + 1, NULL);

    auto moduleHandle = GetModuleHandle("kernel32.dll");

    auto procAddr = GetProcAddress(moduleHandle, "LoadLibraryA");
    CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)procAddr, dllPathAddress, 0, NULL);


    WaitForSingleObject(CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, dllPathAddress, 0, NULL), INFINITE);
    CloseHandle(processHandle);
    VirtualFreeEx(processHandle, dllPathAddress, 0, MEM_RELEASE);
    return 0;
}
