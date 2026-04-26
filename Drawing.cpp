#pragma once
#include "Drawing.h"
#include <cfloat>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include "exMemory.hpp"

struct Vec3 { float x, y, z; };
struct Vec2 { float x, y; };
typedef struct _D3DMATRIX { float m[4][4]; } D3DMATRIX;

static const int CFG_MAX_ENTITIES = 64;
static const int CFG_UPDATE_MS = 10;

struct NPCEntry {
    bool  valid = false;
    bool  hasHealth = false;
    float health = 0.f;
    Vec3  headPos = {};
    Vec3  feetPos = {};
    char  name[64] = "";
    int   listOffset = 0;
};

static NPCEntry   g_buf[2][CFG_MAX_ENTITIES];
static int        g_readBuf = 0;
static int        g_writeBuf = 1;
static std::mutex g_swapMtx;

static exMemory   mem(TARGET_PROCESS, PROCESS_ALL_ACCESS);
static uintptr_t  g_baseModule = 0;
static D3DMATRIX  g_viewMatrix{};
static bool       g_vmValid = false;
static std::atomic<bool> g_workerRunning{ false };

static bool g_espEnabled = true;
static bool g_showBox = true;
static bool g_showSnaplines = true;
static bool g_showHealth = true;
static bool g_showNames = true;
static bool g_showViewMatrix = false;
static bool g_transposeMatrix = true;

inline bool WorldToScreen(const D3DMATRIX& vm, const Vec3& pos, Vec2& out, float sw, float sh)
{
    float cx = pos.x * vm.m[0][0] + pos.y * vm.m[0][1] + pos.z * vm.m[0][2] + vm.m[0][3];
    float cy = pos.x * vm.m[1][0] + pos.y * vm.m[1][1] + pos.z * vm.m[1][2] + vm.m[1][3];
    float cw = pos.x * vm.m[3][0] + pos.y * vm.m[3][1] + pos.z * vm.m[3][2] + vm.m[3][3];

    if (cw < 0.1f) return false;

    float inv = 1.f / cw;
    out.x = (cx * inv + 1.f) * 0.5f * sw;
    out.y = (1.f - cy * inv) * 0.5f * sh;
    return true;
}

void NPCWorkerThread()
{
    while (g_workerRunning.load(std::memory_order_relaxed))
    {
        if (!mem.GetProcessInfo().bAttached || !g_baseModule) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        NPCEntry* out = g_buf[g_writeBuf];
        uint32_t entityListPtr = mem.Read<uint32_t>(g_baseModule + Offsets::Global::EntityList);
        
        if (entityListPtr) {
            for (int i = 0; i < CFG_MAX_ENTITIES; i++)
            {
                NPCEntry& e = out[i];
                uint32_t entityPtr = mem.Read<uint32_t>(entityListPtr + (i * 4));
                
                if (!entityPtr || entityPtr < 0x10000) {
                    e.valid = false;
                    continue;
                }

                int hp = mem.Read<int>(entityPtr + Offsets::Entity::Health);
                if (hp < 1 || hp > 1000) {
                    e.valid = false;
                    continue;
                }

                e.health = (float)hp;
                e.hasHealth = true;
                e.feetPos = mem.Read<Vec3>(entityPtr + Offsets::Entity::Position);
                e.headPos = e.feetPos;
                e.headPos.z += 27.0f; 
                e.valid = true;
                e.listOffset = i;
                sprintf_s(e.name, "Player %d", i);
            }
        }

        {
            std::lock_guard<std::mutex> lk(g_swapMtx);
            g_readBuf = g_writeBuf;
            g_writeBuf = g_writeBuf ^ 1;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(CFG_UPDATE_MS));
    }
}

LPCSTR           Drawing::lpWindowName = "Red Eclipse Overlay";
ImVec2           Drawing::vWindowSize = { 380, 260 };
ImGuiWindowFlags Drawing::WindowFlags = 0;
bool             Drawing::bDraw = true;

bool Drawing::isActive() { return bDraw; }

void Drawing::Draw()
{
    static bool initialized = false;
    if (!initialized) {
        if (mem.GetProcessInfo().bAttached) {
            mem.GetModuleBaseAddress(TARGET_PROCESS, &g_baseModule, "redeclipse.exe");
            if (g_baseModule) {
                initialized = true;
                g_workerRunning = true;
                std::thread(NPCWorkerThread).detach();
            }
        }
    }

    ImDrawList* dl = ImGui::GetBackgroundDrawList();
    ImGuiIO& io = ImGui::GetIO();
    float sw = io.DisplaySize.x, sh = io.DisplaySize.y;
    if (sw <= 0.f || sh <= 0.f) return;

    {
        const char* title = "Red Eclipse Active";
        ImVec2 titleSize = ImGui::CalcTextSize(title);
        dl->AddText(ImVec2(sw * 0.5f - titleSize.x * 0.5f, 15), IM_COL32(0, 255, 255, 255), title);

        char fpsBuf[32];
        sprintf_s(fpsBuf, "FPS: %.0f", io.Framerate);
        ImVec2 fpsSize = ImGui::CalcTextSize(fpsBuf);
        dl->AddText(ImVec2(sw * 0.5f - fpsSize.x * 0.5f, 15 + titleSize.y), IM_COL32(255, 255, 255, 255), fpsBuf);
    }

    if (!initialized) goto draw_menu;

    {
        D3DMATRIX rawVM = mem.Read<D3DMATRIX>(g_baseModule + Offsets::Global::ViewMatrix);
        if (g_transposeMatrix) {
            for (int r = 0; r < 4; r++)
                for (int c = 0; c < 4; c++)
                    g_viewMatrix.m[r][c] = rawVM.m[c][r];
        } else {
            g_viewMatrix = rawVM;
        }
        g_vmValid = true;
    }

    if (g_espEnabled && g_vmValid)
    {
        Vec3 testPoints[] = { { 1347.94f, 1426.56f, 1088.00f } };
        for (const auto& tp : testPoints) {
            Vec2 sPos;
            if (WorldToScreen(g_viewMatrix, tp, sPos, sw, sh)) {
                dl->AddCircleFilled(ImVec2(sPos.x, sPos.y), 4.f, IM_COL32(255, 0, 0, 255));
                dl->AddText(ImVec2(sPos.x + 8, sPos.y - 8), IM_COL32(255, 255, 255, 200), "TEST POINT");
            }
        }

        int rb;
        { std::lock_guard<std::mutex> lk(g_swapMtx); rb = g_readBuf; }
        const NPCEntry* cache = g_buf[rb];

        for (int i = 0; i < CFG_MAX_ENTITIES; i++)
        {
            const NPCEntry& e = cache[i];
            if (!e.valid) continue;

            Vec2 sHead, sFeet;
            bool headOk = WorldToScreen(g_viewMatrix, e.headPos, sHead, sw, sh);
            bool feetOk = WorldToScreen(g_viewMatrix, e.feetPos, sFeet, sw, sh);

            ImU32 col = IM_COL32(0, 255, 255, 255);

            if (headOk && feetOk) {
                float bh = fabsf(sFeet.y - sHead.y);
                float bw = bh * 0.6f;
                float lx = sHead.x - bw * 0.5f;
                float rx = sHead.x + bw * 0.5f;

                if (g_showBox)
                    dl->AddRect(ImVec2(lx, sHead.y), ImVec2(rx, sFeet.y), col, 0.f, 0, 1.0f);

                if (g_showSnaplines)
                    dl->AddLine(ImVec2(sw * 0.5f, sh), ImVec2(sFeet.x, sFeet.y), col, 1.f);

                if (g_showHealth || g_showNames) {
                    char nb[128];
                    if (g_showHealth && e.hasHealth)
                        sprintf_s(nb, "%s [HP: %.0f]", e.name, e.health);
                    else
                        sprintf_s(nb, "%s", e.name);

                    dl->AddText(ImVec2(rx + 3, sHead.y), col, nb);
                }
            }
        }
    }

    if (g_showViewMatrix && g_vmValid) {
        float ox = sw - 420.f, oy = 50.f;
        dl->AddRectFilled(ImVec2(ox - 10, oy - 30), ImVec2(ox + 410, oy + 115), IM_COL32(0, 0, 0, 160));
        dl->AddText(ImVec2(ox, oy - 22), IM_COL32(255, 255, 0, 255), "ViewMatrix (Transposed):");
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++) {
                char mb[24]; sprintf_s(mb, "%.4f", g_viewMatrix.m[r][c]);
                dl->AddText(ImVec2(ox + c * 100.f, oy + r * 25.f), IM_COL32(220, 220, 220, 255), mb);
            }
    }

draw_menu:
    if (bDraw) {
        ImGui::Begin("Red Eclipse ESP", &bDraw);
        ImGui::Checkbox("Enabled", &g_espEnabled);
        ImGui::Checkbox("Box", &g_showBox);
        ImGui::Checkbox("Snaplines", &g_showSnaplines);
        ImGui::Checkbox("Health", &g_showHealth);
        ImGui::Checkbox("Names", &g_showNames);
        ImGui::Checkbox("Show Matrix", &g_showViewMatrix);
        ImGui::Checkbox("Transpose Matrix", &g_transposeMatrix);

        ImGui::Separator();
        ImGui::Text("Base: 0x%llX", g_baseModule);
        ImGui::Text("Attached: %s", mem.GetProcessInfo().bAttached ? "Yes" : "No");
        ImGui::End();
    }

    if (GetAsyncKeyState(MENU_KEY) & 1) bDraw = !bDraw;
}
