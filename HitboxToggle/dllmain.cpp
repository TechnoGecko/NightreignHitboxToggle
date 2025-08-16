#include <Windows.h>
#include <Psapi.h>
#include <cstdint>
#include <cstdio>

const uint8_t damageCtrlPattern[] = {
    0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, // mov rax, [rip+????]
    0x49, 0x8B, 0xD9,                         // mov rbx, r9
    0x49, 0x8B, 0xF8,                         // mov rdi, r8
    0x48, 0x8B, 0xF2,                         // mov rsi, rdx
    0x48, 0x85, 0xC0,                         // test rax, rax
    0x75, 0x2E                                // jne short
};
const char* damageCtrlMask = "xxx????xxxxxxxxxxxx";


uintptr_t AOBScan(const uint8_t* pattern, const char* mask, uintptr_t start, size_t size) {
    for (uintptr_t i = start; i < start + size - strlen(mask); ++i) {
        bool found = true;
        for (size_t j = 0; mask[j]; ++j) {
            if (mask[j] != '?' && pattern[j] != *(uint8_t*)(i + j)) {
                found = false;
                break;
            }
        }
        if (found) return i;
    }
    return 0;
}

DWORD WINAPI MainThread(LPVOID) {
    

    while (true) {
        HMODULE hGame = GetModuleHandle(nullptr);
        if (!hGame) {
            Sleep(5000);
            continue;
        }

        MODULEINFO modInfo{};
        if (!GetModuleInformation(GetCurrentProcess(), hGame, &modInfo, sizeof(modInfo))) {
            Sleep(5000);
            continue;
        }

        uintptr_t base = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
        size_t size = static_cast<size_t>(modInfo.SizeOfImage);

        uintptr_t matchAddr = AOBScan(damageCtrlPattern, damageCtrlMask, base, size);
        if (!matchAddr) {
            Sleep(5000);
            continue;
        }

        int32_t relOffset = *reinterpret_cast<int32_t*>(matchAddr + 3);
        uintptr_t damageCtrlPtrAddr = matchAddr + 7 + relOffset;
        uintptr_t damageCtrl = *reinterpret_cast<uintptr_t*>(damageCtrlPtrAddr);
        if (!damageCtrl) {
            Sleep(5000);
            continue;
        }

        uintptr_t debugFlagAddr = damageCtrl + 0xA0;
        *reinterpret_cast<uint8_t*>(debugFlagAddr) = 1;

        Sleep(5000);
    }

    return 0;
}



BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
    }
    return TRUE;
}