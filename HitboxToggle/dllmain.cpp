#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>

std::atomic<bool> g_Running = true;

const uint8_t damageCtrlPattern[] = {
    0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
    0x49, 0x8B, 0xD9,
    0x49, 0x8B, 0xF8,
    0x48, 0x8B, 0xF2,
    0x48, 0x85, 0xC0,
    0x75, 0x2E
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

void RunHitboxDebug() {
    while (g_Running) {
        HMODULE hGame = GetModuleHandle(nullptr);
        if (!hGame) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        MODULEINFO modInfo{};
        if (!GetModuleInformation(GetCurrentProcess(), hGame, &modInfo, sizeof(modInfo))) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        uintptr_t base = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
        size_t size = static_cast<size_t>(modInfo.SizeOfImage);

        uintptr_t matchAddr = AOBScan(damageCtrlPattern, damageCtrlMask, base, size);
        if (!matchAddr) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        int32_t relOffset = *reinterpret_cast<int32_t*>(matchAddr + 3);
        uintptr_t damageCtrlPtrAddr = matchAddr + 7 + relOffset;
        uintptr_t damageCtrl = *reinterpret_cast<uintptr_t*>(damageCtrlPtrAddr);
        if (!damageCtrl) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        uintptr_t debugFlagAddr = damageCtrl + 0xA0;
        *reinterpret_cast<uint8_t*>(debugFlagAddr) = 1;

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID) {
    static std::thread worker;

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        g_Running = true;
        worker = std::thread(RunHitboxDebug);
        worker.detach();
        break;

    case DLL_PROCESS_DETACH:
        g_Running = false;
        break;
    }
    return TRUE;
}
