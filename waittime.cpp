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
// FINDING THE SITES
//   Addresses move with every game update, so nothing is hard-coded. At startup the plugin
//   scans the exe's .text section for short byte patterns (rip-relative displacements and
//   jump offsets are wildcards) and uses a pattern only if it matches EXACTLY ONE place.
//   A feature whose pattern is missing or ambiguous is skipped and logged; the game is left
//   untouched for it. The same patterns match the original exe and the first update.
//
// WHAT IT CHANGES
//
//   STATION WAIT   timer [rbx+0x68], limit = the 60.0 in xmm8 (shared by a dozen other checks,
//                  so never edited). The one compare that ends the wait
//                      comiss xmm0,xmm8 ; movss [rbx+0x68],xmm0      (9 bytes)
//                  is replaced by a jump to a code cave that does the same two steps against
//                  our own value and jumps back.
//
//   VEHICLE TIME   timer [rbx+0x6c]. The  comiss xmm0,[rip+d]  (380.0, shared with 20 other
//                  instructions) is re-pointed at our own value.
//
//   FREE TIME      timer [rbx+0x30]. TWO places must agree or citizens get stuck:
//                    gate  movss xmm0,[rip+d] ; comiss xmm0,[rbx+0x30] : (60.001, read only
//                          here) the timer keeps accumulating while it is below this.
//                    end   comiss xmm0,xmm8 ; jbe : free time is over once the timer exceeds
//                          xmm8 (60.0).
//                  The gate is re-pointed; the end compare gets a code cave like the station
//                  one. Both are verified before either is written, and the gate is written
//                  first: if the end compare then fails, the result is the vanilla behaviour.
//
//   OPTIONAL (scale_secondary_limit = 1, off by default): [rbx+0x6c] is also checked against
//   a 600.0 held in xmm7 in other branches; this scales that load like the vehicle limit.
//
//   Values scale whatever the game holds by (setting / default setting), so defaults change
//   nothing.

#include <windows.h>

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace {

constexpr const char* kIni = "plugins\\waittime.ini";
constexpr const char* kName = "waittime";
constexpr const char* kVersion = "2.2";

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
// Pattern scanning
// ---------------------------------------------------------------------------
// "siteOff" is where the instruction we care about starts, relative to the match.
struct Pattern {
    const char* name;
    const char* hex;  // hex bytes, "??" = any byte; the first byte must be fixed
    size_t siteOff;
};

constexpr Pattern kStationCmp = {
    "station wait compare",
    // movaps xmm0,xmm6 ; addss xmm0,[rbx+68] ; comiss xmm0,xmm8 ; movss [rbx+68],xmm0 ; jbe rel32
    "0F 28 C6 F3 0F 58 43 68 41 0F 2F C0 F3 0F 11 43 68 0F 86 ?? ?? ?? ??", 8};
constexpr Pattern kVehicleCmp = {
    "vehicle travel compare",
    // addss xmm0,[rbx+6C] ; comiss xmm0,[rip+d] ; movss [rbx+6C],xmm0 ; jbe rel32
    "F3 0F 58 43 6C 0F 2F 05 ?? ?? ?? ?? F3 0F 11 43 6C 0F 86 ?? ?? ?? ??", 5};
constexpr Pattern kFreeEnd = {
    "free time end compare",
    // movss xmm0,[rbx+30] ; comiss xmm0,xmm8 ; jbe rel32
    "F3 0F 10 43 30 41 0F 2F C0 0F 86 ?? ?? ?? ??", 5};
constexpr Pattern kFreeGate = {
    "free time gate",
    // movss xmm0,[rip+d] ; comiss xmm0,[rbx+30] ; jbe rel8
    "F3 0F 10 05 ?? ?? ?? ?? 0F 2F 43 30 76 ??", 0};
constexpr Pattern kLoads = {
    "xmm7/xmm8 limit loads",
    // movss xmm7,[rip+d] ; movaps [r11-68],xmm8 ; movss xmm8,[rip+d]
    "F3 0F 10 3D ?? ?? ?? ?? 45 0F 29 43 98 F3 44 0F 10 05 ?? ?? ?? ??", 0};
constexpr size_t kXmm8LoadOff = 13;  // within kLoads

struct Sig {
    uint8_t b[40];
    uint8_t m[40];  // 0xFF = must match, 0 = wildcard
    size_t n = 0;
};

bool ParseSig(const char* s, Sig& out) {
    out.n = 0;
    while (*s) {
        while (*s == ' ') ++s;
        if (!*s) break;
        if (out.n >= sizeof out.b || !s[1]) return false;
        if (s[0] == '?' && s[1] == '?') {
            out.b[out.n] = 0;
            out.m[out.n] = 0;
        } else {
            char h[3] = {s[0], s[1], 0};
            out.b[out.n] = static_cast<uint8_t>(std::strtoul(h, nullptr, 16));
            out.m[out.n] = 0xFF;
        }
        ++out.n;
        s += 2;
    }
    return out.n > 0 && out.m[0] == 0xFF;
}

// Counts matches (stops at 2); *where = first match.
int Scan(const Sig& s, const uint8_t* lo, size_t size, const uint8_t** where) {
    if (size < s.n) return 0;
    const uint8_t* last = lo + size - s.n;
    int count = 0;
    for (const uint8_t* p = lo; p <= last;) {
        p = static_cast<const uint8_t*>(std::memchr(p, s.b[0], static_cast<size_t>(last - p) + 1));
        if (!p) break;
        bool ok = true;
        for (size_t i = 1; i < s.n && ok; ++i) ok = !s.m[i] || p[i] == s.b[i];
        if (ok) {
            if (count == 0) *where = p;
            if (++count > 1) return count;
        }
        ++p;
    }
    return count;
}

bool TextRange(const uint8_t* base, const uint8_t** lo, size_t* size) {
    uint32_t nt;
    std::memcpy(&nt, base + 0x3C, 4);
    if (std::memcmp(base + nt, "PE\0\0", 4) != 0) return false;
    uint16_t nsec, optSize;
    std::memcpy(&nsec, base + nt + 6, 2);
    std::memcpy(&optSize, base + nt + 20, 2);
    const uint8_t* sh = base + nt + 24 + optSize;
    for (uint16_t i = 0; i < nsec; ++i) {
        const uint8_t* s = sh + i * 40;
        if (std::memcmp(s, ".text\0\0\0", 8) == 0) {
            uint32_t vs, va;
            std::memcpy(&vs, s + 8, 4);
            std::memcpy(&va, s + 12, 4);
            *lo = base + va;
            *size = vs;
            return true;
        }
    }
    return false;
}

// Returns the start of the instruction of interest, or nullptr (logged) if the pattern is
// missing or ambiguous.
uint8_t* Locate(const Pattern& p, const uint8_t* lo, size_t size) {
    Sig s;
    if (!ParseSig(p.hex, s)) {
        g.log("waittime  internal error: bad pattern for %s", p.name);
        return nullptr;
    }
    const uint8_t* where = nullptr;
    int n = Scan(s, lo, size, &where);
    if (n == 0) {
        g.log("waittime  %s: pattern not found - this game version is not supported for that feature", p.name);
        return nullptr;
    }
    if (n > 1) {
        g.log("waittime  %s: pattern matches more than once - refusing", p.name);
        return nullptr;
    }
    uint8_t* site = const_cast<uint8_t*>(where) + p.siteOff;
    g.log("waittime  found %-24s at rva 0x%X", p.name, static_cast<unsigned>(site - g.base));
    return site;
}

// ---------------------------------------------------------------------------
// Patching helpers
// ---------------------------------------------------------------------------
constexpr uint8_t kStationCmpOrig[9] = {0x41, 0x0F, 0x2F, 0xC0, 0xF3, 0x0F, 0x11, 0x43, 0x68};
constexpr size_t kFreeCmpLen = 10;  // comiss xmm0,xmm8 (4) + jbe rel32 (6)

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

// Reads the float that the rip-relative instruction at `ins` (opcode length opLen) points at.
bool ReadRipFloat(const char* label, uint8_t* ins, size_t opLen, uint8_t** dispPtr, uint8_t** instrEnd, float* value) {
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

    // ---- locate everything --------------------------------------------------------
    const uint8_t* textLo = nullptr;
    size_t textSize = 0;
    if (!TextRange(g.base, &textLo, &textSize)) {
        g.log("waittime  could not read the executable's section table - inactive");
        return 1;
    }
    uint8_t* stationCmp = Locate(kStationCmp, textLo, textSize);
    uint8_t* vehicleCmp = Locate(kVehicleCmp, textLo, textSize);
    uint8_t* freeEnd = Locate(kFreeEnd, textLo, textSize);
    uint8_t* freeGate = Locate(kFreeGate, textLo, textSize);
    uint8_t* loads = Locate(kLoads, textLo, textSize);
    uint8_t* xmm7Load = loads;
    uint8_t* xmm8Load = loads ? loads + kXmm8LoadOff : nullptr;

    uint8_t* hint = stationCmp ? stationCmp : vehicleCmp ? vehicleCmp : freeEnd ? freeEnd : freeGate;
    uint8_t* block = nullptr;

    auto getBlock = [&]() -> uint8_t* {
        if (block) return block;
        if (!hint) return nullptr;
        block = static_cast<uint8_t*>(g.allocNear(hint, kBlockSize));
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
    if (xmm8Load) {
        uint8_t *dp, *ie;
        have60 = ReadRipFloat("xmm8 limit", xmm8Load, 5, &dp, &ie, &base60);
    }

    // ---- station wait --------------------------------------------------------------
    {
        uint8_t* cmp = stationCmp;
        if (!cmp || !have60) {
            g.log("waittime  station wait: skipped (site not located)");
            ++failed;
        } else {
            float value = static_cast<float>(static_cast<double>(base60) * stationRatio);
            uint8_t* b = nullptr;
            if (g_probe) {
                g.log("waittime  probe: station wait  limit %.3f (would become %.3f)", static_cast<double>(base60),
                      static_cast<double>(value));
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
                    EmitComissSlot(c, b + kSlotStation);  // comiss xmm0,[limit]
                    const uint8_t mv[5] = {0xF3, 0x0F, 0x11, 0x43, 0x68};
                    std::memcpy(c + 7, mv, 5);            // movss [rbx+0x68],xmm0
                    EmitJmp(c + 12, backTo);              // jmp back
                    FlushInstructionCache(GetCurrentProcess(), b, kBlockSize);

                    // jmp cave ; nop x4   (overwrites comiss + movss, 9 bytes)
                    uint8_t jmp[sizeof kStationCmpOrig] = {0xE9, 0, 0, 0, 0, 0x90, 0x90, 0x90, 0x90};
                    int32_t fwd = static_cast<int32_t>(c - (cmp + 5));
                    std::memcpy(jmp + 1, &fwd, 4);
                    if (Patch(cmp, jmp, sizeof jmp)) {
                        ++applied;
                        g.log("waittime  station wait  %.3f -> %.3f  (%.2f h)", static_cast<double>(base60),
                              static_cast<double>(value), g_stationHours);
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
        if (!vehicleCmp || !ReadRipFloat("vehicle travel", vehicleCmp, 3, &dispPtr, &instrEnd, &cur)) {
            if (!vehicleCmp) g.log("waittime  vehicle travel: skipped (site not located)");
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
                g.log("waittime  vehicle travel %.3f -> %.3f  (%.2f h)", static_cast<double>(cur),
                      static_cast<double>(value), g_vehicleHours);
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
        uint8_t* cmp = freeEnd;
        uint8_t* jbeTarget = nullptr;
        bool ok = have60 && cmp && freeGate;
        if (!ok) g.log("waittime  free time: skipped (site not located)");
        if (ok) ok = ReadRipFloat("free time gate", freeGate, 4, &gateDisp, &gateEnd, &gateCur);
        if (ok && (gateCur < 55.0f || gateCur > 65.0f)) {
            g.log("waittime  free time gate holds %.3f, expected about 60 - refusing", static_cast<double>(gateCur));
            ok = false;
        }
        if (ok) {
            int32_t rel;
            std::memcpy(&rel, cmp + 6, 4);  // after comiss xmm0,xmm8 (4) + 0F 86 (2)
            jbeTarget = cmp + kFreeCmpLen + rel;
            if (rel <= 0 || rel > 0x2000) {
                g.log("waittime  free time: end compare jumps somewhere unexpected - refusing");
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
                g.log("waittime  probe: free time  end %.3f (would become %.3f), gate %.3f (would become %.3f)",
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
                            g.log("waittime  free time  end %.3f -> %.3f, gate %.3f -> %.3f  (%.2f h)",
                                  static_cast<double>(base60), static_cast<double>(endValue), static_cast<double>(gateCur),
                                  static_cast<double>(gateValue), g_freeHours);
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
        if (!xmm7Load || !ReadRipFloat("secondary limit", xmm7Load, 4, &dispPtr, &instrEnd, &cur)) {
            if (!xmm7Load) g.log("waittime  secondary limit: skipped (site not located)");
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
                g.log("waittime  secondary limit %.3f -> %.3f", static_cast<double>(cur), static_cast<double>(value));
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
