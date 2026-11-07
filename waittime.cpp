// waittime - tesmiomodloader plugin (plugin API v4)
// Copyright (C) 2026
// Licensed under the GNU General Public License v3.0 or later (see LICENSE).
//
// Build on Linux (MinGW-w64):
//   x86_64-w64-mingw32-g++ -std=c++17 -O2 -shared -static -static-libgcc -static-libstdc++ -o waittime.dll waittime.cpp
// Build on Windows: see build.bat. Install: waittime.dll + waittime.ini in the loader's plugins folder.
//
// The host interface is inferred from walking.dll / walkspeed.dll (see HOST ABI below).
//
// WHAT IT CHANGES (RVAs in SOVIET64.exe)
//
//   STATION WAIT   timer [rbx+0x68], limit = the 60.0 in xmm8 (shared by a dozen other checks,
//                  so never edited). The one compare that ends the wait
//                      0x833FD3  comiss xmm0,xmm8 ; movss [rbx+0x68],xmm0
//                  is replaced by a jump to a code cave that does the same two steps against
//                  our own value and jumps back.
//
//   VEHICLE TIME   timer [rbx+0x6c]. 0x8341A1  comiss xmm0,[rip+d]  (380.0, shared with 20
//                  other instructions) is re-pointed at our own value.
//
//   FREE TIME      timer [rbx+0x30]. TWO places must agree or citizens get stuck:
//                    gate  0x8339CF  movss xmm0,[rip+d]  (60.001, read only here): the timer
//                                    keeps accumulating while it is below this.
//                    end   0x833A40  comiss xmm0,xmm8 ; jbe 0x833E2B : free time is over once
//                                    the timer exceeds xmm8 (60.0).
//                  The gate is re-pointed; the end compare gets a code cave like the station
//                  one. Both are verified before either is written, and the gate is written
//                  first: if the end compare then fails, the result is the vanilla behaviour
//                  (the timer passes 60 on its way to the raised gate).
//
//   OPTIONAL (scale_secondary_limit = 1, off by default): [rbx+0x6c] is also checked against
//   a 600.0 held in xmm7 in other branches; this scales that load like the vehicle limit.
//
//   Every site checks its original bytes first and refuses to write if they differ. Values
//   scale whatever the game holds by (setting / default setting), so defaults change nothing.

#include <windows.h>

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace {

constexpr const char* kIni = "plugins\\waittime.ini";
constexpr const char* kName = "waittime";
constexpr const char* kVersion = "2.1";

// ---------------------------------------------------------------------------
// HOST ABI (inferred)
//   TsmPluginApiVersion()          -> 4
//   TsmPluginInit(host, out)       out[0]=name, out[1]=version; 0 = stay loaded, non-zero = unload
//   TsmPluginStart()               do the patching; 0 = ok, non-zero = inactive
//   host+0x04 u32 struct size      host+0x10 game image base
//   host+0x38 log(fmt, ...)        host+0x58 allocNear(near, n)
//   host+0x70 iniInt(path, section, key, default) -> int
//   host+0x78 iniStr(path, section, key, out, outSize, default) -> nonzero if read
// ---------------------------------------------------------------------------
using LogFn = void (*)(const char* fmt, ...);
using IniIntFn = int (*)(const char*, const char*, const char*, int);
using IniStrFn = int (*)(const char*, const char*, const char*, char*, int, const char*);
using AllocNearFn = void* (*)(void* nearAddr, uint32_t size);

struct HostApi {
    uint8_t* base = nullptr;
    LogFn log = nullptr;
    IniIntFn iniInt = nullptr;
    IniStrFn iniStr = nullptr;
    AllocNearFn allocNear = nullptr;
} g;

template <class T>
T HostField(const void* host, size_t off) {
    return reinterpret_cast<T>(*reinterpret_cast<void* const*>(static_cast<const uint8_t*>(host) + off));
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------
constexpr double kBaseStationHours = 1.0;
constexpr double kBaseVehicleHours = 4.0;
constexpr double kBaseFreeHours = 16.0;
constexpr double kMaxHours = 10000.0;

double g_stationHours = kBaseStationHours;
double g_vehicleHours = kBaseVehicleHours;
double g_freeHours = kBaseFreeHours;
bool g_enabled = true;
bool g_probe = false;
bool g_secondary = false;

double ReadHours(const char* key, double fallback) {
    char buf[64] = {};
    if (!g.iniStr(kIni, "general", key, buf, sizeof buf, "") || buf[0] == '\0') return fallback;
    char* end = nullptr;
    double v = std::strtod(buf, &end);
    if (end == buf || *end != '\0' || !std::isfinite(v) || v <= 0.0 || v > kMaxHours) {
        g.log("waittime  %s = '%s' is not a number in (0, %.0f] - using %.2f", key, buf, kMaxHours, fallback);
        return fallback;
    }
    return v;
}

void LoadSettings() {
    g_enabled = g.iniInt(kIni, "general", "enabled", 1) != 0;
    g_probe = g.iniInt(kIni, "general", "probe", 0) != 0;
    g_secondary = g.iniInt(kIni, "general", "scale_secondary_limit", 0) != 0;
    g_stationHours = ReadHours("station_wait_hours", kBaseStationHours);
    g_vehicleHours = ReadHours("vehicle_travel_hours", kBaseVehicleHours);
    g_freeHours = ReadHours("free_time_hours", kBaseFreeHours);
}

// ---------------------------------------------------------------------------
// Sites
// ---------------------------------------------------------------------------
constexpr uint32_t kXmm8LoadRva = 0x832F28;    // movss xmm8,[rip+d]  -> 60.0 (read only, never changed)
constexpr uint32_t kStationCmpRva = 0x833FD3;  // comiss xmm0,xmm8 ; movss [rbx+0x68],xmm0
constexpr uint32_t kVehicleRva = 0x8341A1;     // comiss xmm0,[rip+d] -> 380.0
constexpr uint32_t kSecondaryRva = 0x832F1B;   // movss xmm7,[rip+d]  -> 600.0
constexpr uint32_t kFreeGateRva = 0x8339CF;    // movss xmm0,[rip+d]  -> 60.001
constexpr uint32_t kFreeCmpRva = 0x833A40;     // comiss xmm0,xmm8 ; jbe rel32
constexpr uint32_t kFreeCmpTargetRva = 0x833E2B;

constexpr uint8_t kXmm8LoadOp[5] = {0xF3, 0x44, 0x0F, 0x10, 0x05};
constexpr uint8_t kStationCmpOrig[9] = {0x41, 0x0F, 0x2F, 0xC0, 0xF3, 0x0F, 0x11, 0x43, 0x68};
constexpr uint8_t kVehicleOp[3] = {0x0F, 0x2F, 0x05};
constexpr uint8_t kSecondaryOp[4] = {0xF3, 0x0F, 0x10, 0x3D};
constexpr uint8_t kFreeGateOp[4] = {0xF3, 0x0F, 0x10, 0x05};
constexpr uint8_t kFreeCmpOp[6] = {0x41, 0x0F, 0x2F, 0xC0, 0x0F, 0x86};  // comiss xmm0,xmm8 ; jbe (rel32 follows)
constexpr size_t kFreeCmpLen = 10;                                        // 6 opcode bytes + rel32

// Layout of the block next to the exe (code caves + our float slots)
constexpr uint32_t kBlockSize = 0x80;
constexpr uint32_t kCaveStation = 0x00;  // 17 bytes
constexpr uint32_t kCaveFree = 0x20;     // 18 bytes
constexpr uint32_t kSlotStation = 0x40;
constexpr uint32_t kSlotVehicle = 0x44;
constexpr uint32_t kSlotSecondary = 0x48;
constexpr uint32_t kSlotFreeEnd = 0x4C;
constexpr uint32_t kSlotFreeGate = 0x50;

bool Patch(void* dst, const void* src, size_t n) {
    DWORD old = 0;
    if (!VirtualProtect(dst, n, PAGE_EXECUTE_READWRITE, &old)) {
        g.log("waittime  VirtualProtect failed at %p", dst);
        return false;
    }
    std::memcpy(dst, src, n);
    VirtualProtect(dst, n, old, &old);
    FlushInstructionCache(GetCurrentProcess(), dst, n);
    return true;
}

bool NearEnough(const uint8_t* from, const uint8_t* to) {
    int64_t d = to - from;
    return d >= INT32_MIN && d <= INT32_MAX;
}

// Checks the opcode at rva, then reads the float its rip-relative operand points at.
bool ResolveRipFloat(const char* label, uint32_t rva, const uint8_t* op, size_t opLen, uint8_t** dispPtr,
                     uint8_t** instrEnd, float* value) {
    uint8_t* ins = g.base + rva;
    if (std::memcmp(ins, op, opLen) != 0) {
        g.log("waittime  %s: rva 0x%X holds %02X %02X %02X %02X, not the expected instruction - refusing", label, rva,
              ins[0], ins[1], ins[2], ins[3]);
        return false;
    }
    int32_t disp;
    std::memcpy(&disp, ins + opLen, 4);
    *dispPtr = ins + opLen;
    *instrEnd = ins + opLen + 4;
    std::memcpy(value, *instrEnd + disp, 4);
    if (!std::isfinite(*value) || *value <= 0.0f || *value > 1e7f) {
        g.log("waittime  %s: constant reads %g, not a plausible limit - refusing", label, static_cast<double>(*value));
        return false;
    }
    return true;
}

// Re-point one rip-relative instruction at our own float.
bool Repoint(const char* label, uint8_t* dispPtr, uint8_t* instrEnd, uint8_t* slot, float value) {
    if (!NearEnough(instrEnd, slot)) {
        g.log("waittime  %s: slot is out of rel32 range - refusing", label);
        return false;
    }
    std::memcpy(slot, &value, 4);  // our memory: fill before the game can read it
    int32_t nd = static_cast<int32_t>(slot - instrEnd);
    return Patch(dispPtr, &nd, 4);
}

// Code emitters (write into the cave; `at` is the cave address, which is final).
void EmitComissSlot(uint8_t* at, const uint8_t* slot) {  // comiss xmm0,[slot]  (7 bytes)
    int32_t d = static_cast<int32_t>(slot - (at + 7));
    at[0] = 0x0F; at[1] = 0x2F; at[2] = 0x05;
    std::memcpy(at + 3, &d, 4);
}
void EmitJmp(uint8_t* at, const uint8_t* to) {  // jmp rel32  (5 bytes)
    int32_t d = static_cast<int32_t>(to - (at + 5));
    at[0] = 0xE9;
    std::memcpy(at + 1, &d, 4);
}
void EmitJbe(uint8_t* at, const uint8_t* to) {  // jbe rel32  (6 bytes)
    int32_t d = static_cast<int32_t>(to - (at + 6));
    at[0] = 0x0F; at[1] = 0x86;
    std::memcpy(at + 2, &d, 4);
}

}  // namespace

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
extern "C" {

__declspec(dllexport) int TsmPluginApiVersion() { return 4; }

__declspec(dllexport) int TsmPluginInit(const void* host, const char** out) {
    if (!host || !out) return 1;
    if (*reinterpret_cast<const uint32_t*>(static_cast<const uint8_t*>(host) + 4) < 0x80) return 1;  // host too old

    g.base = HostField<uint8_t*>(host, 0x10);
    g.log = HostField<LogFn>(host, 0x38);
    g.allocNear = HostField<AllocNearFn>(host, 0x58);
    g.iniInt = HostField<IniIntFn>(host, 0x70);
    g.iniStr = HostField<IniStrFn>(host, 0x78);

    out[0] = kName;
    out[1] = kVersion;

    LoadSettings();
    if (!g_enabled) {
        g.log("waittime  disabled");
        return 1;
    }
    g.log("waittime  init (station wait %.2f h, vehicle travel %.2f h, free time %.2f h%s)", g_stationHours,
          g_vehicleHours, g_freeHours, g_secondary ? ", secondary limit scaled" : "");
    return 0;
}

__declspec(dllexport) int TsmPluginStart() {
    const double stationRatio = g_stationHours / kBaseStationHours;
    const double vehicleRatio = g_vehicleHours / kBaseVehicleHours;
    const double freeRatio = g_freeHours / kBaseFreeHours;
    const bool stationChange = std::fabs(stationRatio - 1.0) > 1e-9;
    const bool vehicleChange = std::fabs(vehicleRatio - 1.0) > 1e-9;
    const bool freeChange = std::fabs(freeRatio - 1.0) > 1e-9;

    int applied = 0, failed = 0;
    uint8_t* block = nullptr;

    auto getBlock = [&]() -> uint8_t* {
        if (block) return block;
        block = static_cast<uint8_t*>(g.allocNear(g.base + kStationCmpRva, kBlockSize));
        if (!block) {
            g.log("waittime  no allocation within reach of the executable");
            return nullptr;
        }
        DWORD old = 0;
        if (!VirtualProtect(block, kBlockSize, PAGE_EXECUTE_READWRITE, &old)) {
            g.log("waittime  could not make the code cave executable");
            block = nullptr;
            return nullptr;
        }
        std::memset(block, 0, kBlockSize);
        return block;
    };

    // The 60.0 that xmm8 holds: base value for both compares that use a code cave.
    float base60 = 0.0f;
    bool have60 = false;
    {
        uint8_t *dp, *ie;
        have60 = ResolveRipFloat("xmm8 limit", kXmm8LoadRva, kXmm8LoadOp, sizeof kXmm8LoadOp, &dp, &ie, &base60);
    }

    // ---- station wait --------------------------------------------------------------
    {
        uint8_t* cmp = g.base + kStationCmpRva;
        bool ok = have60;
        if (ok && std::memcmp(cmp, kStationCmpOrig, sizeof kStationCmpOrig) != 0) {
            g.log("waittime  station wait: compare at rva 0x%X is not the expected instruction - refusing", kStationCmpRva);
            ok = false;
        }
        if (!ok) {
            ++failed;
        } else {
            float value = static_cast<float>(static_cast<double>(base60) * stationRatio);
            uint8_t* b = nullptr;
            if (g_probe) {
                g.log("waittime  probe: station wait  limit %.3f (would become %.3f), compare at 0x%X ok",
                      static_cast<double>(base60), static_cast<double>(value), kStationCmpRva);
            } else if (!stationChange) {
                g.log("waittime  station wait  unchanged (%.3f)", static_cast<double>(base60));
            } else if ((b = getBlock()) == nullptr) {
                ++failed;
            } else {
                uint8_t* c = b + kCaveStation;
                uint8_t* backTo = cmp + sizeof kStationCmpOrig;  // the jbe that follows
                if (!NearEnough(cmp + 5, c) || !NearEnough(c + 12 + 5, backTo)) {
                    g.log("waittime  station wait: code cave is out of jump range - refusing");
                    ++failed;
                } else {
                    std::memcpy(b + kSlotStation, &value, 4);
                    EmitComissSlot(c, b + kSlotStation);            // comiss xmm0,[limit]
                    const uint8_t mv[5] = {0xF3, 0x0F, 0x11, 0x43, 0x68};
                    std::memcpy(c + 7, mv, 5);                      // movss [rbx+0x68],xmm0
                    EmitJmp(c + 12, backTo);                        // jmp back
                    FlushInstructionCache(GetCurrentProcess(), b, kBlockSize);

                    // jmp cave ; nop x4   (overwrites comiss + movss, 9 bytes)
                    uint8_t jmp[sizeof kStationCmpOrig] = {0xE9, 0, 0, 0, 0, 0x90, 0x90, 0x90, 0x90};
                    int32_t fwd = static_cast<int32_t>(c - (cmp + 5));
                    std::memcpy(jmp + 1, &fwd, 4);
                    if (Patch(cmp, jmp, sizeof jmp)) {
                        ++applied;
                        g.log("waittime  station wait  %.3f -> %.3f  (%.2f h, compare at rva 0x%X)", static_cast<double>(base60),
                              static_cast<double>(value), g_stationHours, kStationCmpRva);
                    } else {
                        ++failed;
                    }
                }
            }
        }
    }

    // ---- vehicle time --------------------------------------------------------------
    {
        uint8_t *dispPtr, *instrEnd;
        float cur;
        if (!ResolveRipFloat("vehicle travel", kVehicleRva, kVehicleOp, sizeof kVehicleOp, &dispPtr, &instrEnd, &cur)) {
            ++failed;
        } else {
            float value = static_cast<float>(static_cast<double>(cur) * vehicleRatio);
            uint8_t* b = nullptr;
            if (g_probe) {
                g.log("waittime  probe: vehicle travel limit %.3f (would become %.3f)", static_cast<double>(cur),
                      static_cast<double>(value));
            } else if (!vehicleChange) {
                g.log("waittime  vehicle travel unchanged (%.3f)", static_cast<double>(cur));
            } else if ((b = getBlock()) == nullptr) {
                ++failed;
            } else if (Repoint("vehicle travel", dispPtr, instrEnd, b + kSlotVehicle, value)) {
                ++applied;
                g.log("waittime  vehicle travel %.3f -> %.3f  (%.2f h, rva 0x%X)", static_cast<double>(cur),
                      static_cast<double>(value), g_vehicleHours, kVehicleRva);
            } else {
                ++failed;
            }
        }
    }

    // ---- free time -----------------------------------------------------------------
    // Gate and end compare must agree, so verify both before writing either.
    {
        uint8_t *gateDisp = nullptr, *gateEnd = nullptr;
        float gateCur = 0.0f;
        uint8_t* cmp = g.base + kFreeCmpRva;
        uint8_t* jbeTarget = nullptr;
        bool ok = have60;
        if (ok) ok = ResolveRipFloat("free time gate", kFreeGateRva, kFreeGateOp, sizeof kFreeGateOp, &gateDisp, &gateEnd, &gateCur);
        if (ok && (gateCur < 55.0f || gateCur > 65.0f)) {
            g.log("waittime  free time gate holds %.3f, expected about 60 - refusing", static_cast<double>(gateCur));
            ok = false;
        }
        if (ok && std::memcmp(cmp, kFreeCmpOp, sizeof kFreeCmpOp) != 0) {
            g.log("waittime  free time: compare at rva 0x%X is not the expected instruction - refusing", kFreeCmpRva);
            ok = false;
        }
        if (ok) {
            int32_t rel;
            std::memcpy(&rel, cmp + sizeof kFreeCmpOp, 4);
            jbeTarget = cmp + kFreeCmpLen + rel;
            if (jbeTarget != g.base + kFreeCmpTargetRva) {
                g.log("waittime  free time: compare at rva 0x%X jumps somewhere unexpected - refusing", kFreeCmpRva);
                ok = false;
            }
        }
        if (!ok) {
            ++failed;
        } else {
            float endValue = static_cast<float>(static_cast<double>(base60) * freeRatio);
            float gateValue = static_cast<float>(static_cast<double>(gateCur) * freeRatio);
            uint8_t* b = nullptr;
            if (g_probe) {
                g.log("waittime  probe: free time  end %.3f (would become %.3f), gate %.3f (would become %.3f), both sites ok",
                      static_cast<double>(base60), static_cast<double>(endValue), static_cast<double>(gateCur),
                      static_cast<double>(gateValue));
            } else if (!freeChange) {
                g.log("waittime  free time  unchanged (%.3f)", static_cast<double>(base60));
            } else if ((b = getBlock()) == nullptr) {
                ++failed;
            } else {
                uint8_t* c = b + kCaveFree;
                uint8_t* backTo = cmp + kFreeCmpLen;  // the instruction after the jbe
                if (!NearEnough(cmp + 5, c) || !NearEnough(c + 13 + 5, backTo) || !NearEnough(c + 7 + 6, jbeTarget) ||
                    !NearEnough(gateEnd, b + kSlotFreeGate)) {
                    g.log("waittime  free time: code cave is out of jump range - refusing");
                    ++failed;
                } else {
                    // 1. cave (not reachable until the site is patched)
                    std::memcpy(b + kSlotFreeEnd, &endValue, 4);
                    EmitComissSlot(c, b + kSlotFreeEnd);  // comiss xmm0,[limit]
                    EmitJbe(c + 7, jbeTarget);            // jbe <original target>
                    EmitJmp(c + 13, backTo);              // jmp back
                    FlushInstructionCache(GetCurrentProcess(), b, kBlockSize);

                    // 2. gate first: if step 3 fails the game behaves as vanilla
                    if (!Repoint("free time gate", gateDisp, gateEnd, b + kSlotFreeGate, gateValue)) {
                        ++failed;
                    } else {
                        // 3. end compare: jmp cave ; nop x5   (overwrites comiss + jbe, 10 bytes)
                        uint8_t jmp[kFreeCmpLen] = {0xE9, 0, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0x90};
                        int32_t fwd = static_cast<int32_t>(c - (cmp + 5));
                        std::memcpy(jmp + 1, &fwd, 4);
                        if (Patch(cmp, jmp, sizeof jmp)) {
                            ++applied;
                            g.log("waittime  free time  end %.3f -> %.3f, gate %.3f -> %.3f  (%.2f h)", static_cast<double>(base60),
                                  static_cast<double>(endValue), static_cast<double>(gateCur), static_cast<double>(gateValue),
                                  g_freeHours);
                        } else {
                            g.log("waittime  free time: gate raised but end compare not patched - behaves as vanilla");
                            ++failed;
                        }
                    }
                }
            }
        }
    }

    // ---- optional: secondary limit on the vehicle timer ------------------------------
    if (g_secondary) {
        uint8_t *dispPtr, *instrEnd;
        float cur;
        if (!ResolveRipFloat("secondary limit", kSecondaryRva, kSecondaryOp, sizeof kSecondaryOp, &dispPtr, &instrEnd, &cur)) {
            ++failed;
        } else {
            float value = static_cast<float>(static_cast<double>(cur) * vehicleRatio);
            uint8_t* b = nullptr;
            if (g_probe) {
                g.log("waittime  probe: secondary limit %.3f (would become %.3f)", static_cast<double>(cur),
                      static_cast<double>(value));
            } else if (!vehicleChange) {
                g.log("waittime  secondary limit unchanged (%.3f)", static_cast<double>(cur));
            } else if ((b = getBlock()) == nullptr) {
                ++failed;
            } else if (Repoint("secondary limit", dispPtr, instrEnd, b + kSlotSecondary, value)) {
                ++applied;
                g.log("waittime  secondary limit %.3f -> %.3f  (rva 0x%X)", static_cast<double>(cur), static_cast<double>(value),
                      kSecondaryRva);
            } else {
                ++failed;
            }
        }
    }

    if (g_probe) return 1;  // probe never leaves anything patched
    if (failed > 0 && applied == 0) {
        g.log("waittime  nothing could be patched - inactive");
        return 1;
    }
    return 0;
}

}  // extern "C"
