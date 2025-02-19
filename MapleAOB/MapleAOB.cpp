#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <regex>
#include <thread>
#include <string>
#include <string_view>
#include <cctype>
#include <algorithm>
using namespace std;

string GetExeDirectory() {
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    string exePath(path);
    size_t pos = exePath.find_last_of("\\/");
    return (pos != string::npos) ? exePath.substr(0, pos) : exePath;
}

DWORD GetProcessID(const string& processName) {
    DWORD processID = 0;
    while (!processID) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return 0;
        PROCESSENTRY32 pe = { 0 };
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe))
            do {
                if (_stricmp(pe.szExeFile, processName.c_str()) == 0) {
                    processID = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(snap, &pe));
        CloseHandle(snap);
        if (!processID) {
            cout << "Waiting for " << processName << "...\n";
            this_thread::sleep_for(chrono::seconds(2));
        }
    }
    return processID;
}

HANDLE OpenTargetProcess(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc)
        cerr << "Error: Unable to open process.\n";
    return hProc;
}

vector<MEMORY_BASIC_INFORMATION> GetMemoryRegions(HANDLE hProc, bool) {
    vector<MEMORY_BASIC_INFORMATION> regions;
    regions.reserve(100);
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t addr = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
    uintptr_t maxAddr = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);
    while (addr < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi))
            break;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY)))
            regions.push_back(mbi);
        addr += mbi.RegionSize;
    }
    return regions;
}

vector<int> PatternToBytes(string_view pattern) {
    vector<int> bytes;
    bytes.reserve(16);
    size_t start = 0;
    while (start < pattern.size()) {
        while (start < pattern.size() && isspace(static_cast<unsigned char>(pattern[start])))
            start++;
        if (start >= pattern.size())
            break;
        size_t end = pattern.find(' ', start);
        if (end == string_view::npos)
            end = pattern.size();
        auto token = pattern.substr(start, end - start);
        if (token == "??" || token == "?")
            bytes.push_back(-1);
        else
            bytes.push_back(stoi(string(token), nullptr, 16));
        start = end;
    }
    return bytes;
}

uintptr_t FindPattern(HANDLE hProc, const vector<MEMORY_BASIC_INFORMATION>& regions, const vector<int>& pattern) {
    size_t patSize = pattern.size();
    vector<BYTE> buffer;
    for (const auto& reg : regions) {
        if (buffer.size() < reg.RegionSize)
            buffer.resize(reg.RegionSize);
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(reg.BaseAddress), buffer.data(), reg.RegionSize, &bytesRead))
            continue;
        for (size_t i = 0; i <= bytesRead - patSize; i++) {
            bool found = true;
            for (size_t j = 0; j < patSize; j++) {
                if (pattern[j] != -1 && buffer[i + j] != static_cast<BYTE>(pattern[j])) {
                    found = false;
                    break;
                }
            }
            if (found)
                return reinterpret_cast<uintptr_t>(reg.BaseAddress) + i;
        }
    }
    return 0;
}

vector<pair<string, vector<int>>> ReadPatterns(const string& filename, bool is64Bit) {
    ifstream file(filename);
    if (!file) {
        cerr << "Error: Unable to open pattern file: " << filename << "\n";
        return {};
    }
    vector<pair<string, vector<int>>> patterns;
    patterns.reserve(8);
    string line;
    regex patternRegex(R"((\w+)\s*=\s*\"([0-9A-Fa-f?\s]+)\")");
    int currentSection = 0;
    while (getline(file, line)) {
        line = regex_replace(line, regex("^\\s+|\\s+$"), "");
        if (line.empty())
            continue;
        if (line[0] == '#') {
            if (line.find("32BIT") != string::npos)
                currentSection = 32;
            else if (line.find("64BIT") != string::npos)
                currentSection = 64;
            else
                currentSection = 0;
            continue;
        }
        if (currentSection != 0 && ((is64Bit && currentSection != 64) || (!is64Bit && currentSection != 32)))
            continue;
        smatch matches;
        if (regex_search(line, matches, patternRegex))
            patterns.emplace_back(matches[1].str(), PatternToBytes(matches[2].str()));
    }
    return patterns;
}

void SaveResults(const vector<pair<string, uintptr_t>>& results, const string& filePath, bool is64Bit) {
    vector<string> lines;
    {
        ifstream inFile(filePath);
        string l;
        while (getline(inFile, l))
            lines.push_back(l);
    }
    auto initSections = [&]() {
        lines = { "64BIT Addresses:", "###################", "32BIT Addresses:", "###################" };
        };
    if (lines.size() < 4)
        initSections();
    else if (lines[0].find("64BIT Addresses:") == string::npos ||
        lines[1].find("###################") == string::npos ||
        lines[2].find("32BIT Addresses:") == string::npos ||
        lines[3].find("###################") == string::npos)
        initSections();
    vector<string> sec64, sec32;
    enum Section { NONE, SEC64, SEC32 } cur = NONE;
    for (const auto& l : lines) {
        if (l.find("64BIT Addresses:") != string::npos) { cur = SEC64; continue; }
        if (l.find("32BIT Addresses:") != string::npos) { cur = SEC32; continue; }
        if (l.find("###################") != string::npos)
            continue;
        if (cur == SEC64)
            sec64.push_back(l);
        else if (cur == SEC32)
            sec32.push_back(l);
    }
    ostringstream oss;
    for (const auto& r : results)
        oss << r.first << " Address: 0x" << hex << uppercase << r.second << "\n";
    string newResults = oss.str();
    istringstream iss(newResults);
    string ln;
    if (is64Bit) {
        while (getline(iss, ln))
            sec64.push_back(ln);
    }
    else {
        while (getline(iss, ln))
            sec32.push_back(ln);
    }
    ofstream outFile(filePath, ios::trunc);
    outFile << "64BIT Addresses:\n###################\n";
    for (const auto& s : sec64)
        outFile << s << "\n";
    outFile << "32BIT Addresses:\n###################\n";
    for (const auto& s : sec32)
        outFile << s << "\n";
    cout << "Results saved to " << filePath << "\n";
}

int main() {
    cout << "Select architecture (32/64): ";
    string arch; cin >> arch;
    bool is64Bit = (arch == "64");
    cout << "Waiting for MapleStory.exe...\n";
    DWORD pid = GetProcessID("MapleStory.exe");
    HANDLE hProc = OpenTargetProcess(pid);
    if (!hProc) { cerr << "Error: Unable to open process.\n"; return 1; }
    string exeDir = GetExeDirectory();
    string patternsPath = exeDir + "\\patterns.txt";
    cout << "Reading patterns from " << patternsPath << "...\n";
    auto patterns = ReadPatterns(patternsPath, is64Bit);
    if (patterns.empty()) { cerr << "Error: No patterns loaded.\n"; return 1; }
    cout << "Scanning memory...\n";
    auto regions = GetMemoryRegions(hProc, is64Bit);
    vector<pair<string, uintptr_t>> results;
    results.reserve(patterns.size());
    for (auto& pat : patterns) {
        uintptr_t addr = FindPattern(hProc, regions, pat.second);
        if (addr) {
            results.emplace_back(pat.first, addr);
            cout << "Found " << pat.first << " at 0x" << hex << uppercase << addr << "\n";
        }
        else {
            cout << pat.first << " not found.\n";
        }
    }
    CloseHandle(hProc);
    string updateFile = exeDir + "\\update.txt";
    SaveResults(results, updateFile, is64Bit);
    return 0;
}
