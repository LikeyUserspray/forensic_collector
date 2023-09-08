#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Output.H>
#include <FL/Fl_Check_Button.H>
#include <FL/Fl_File_Chooser.H>
#include <FL/Fl_Text_Display.H>
#include <FL/Fl_Text_Buffer.H>
#include <FL/Fl_Native_File_Chooser.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Choice.H>
#include <windows.h>
#include <winevt.h>
#include <wincrypt.h>
#include <fstream>
#include <string>
#include <filesystem>
#include <iostream>
#include <vector>
#include <locale>
#include <codecvt>

// �̺�Ʈ ������ �α׸� ó���ϱ� ���� Windows Event Log API 
#pragma comment(lib, "wevtapi.lib")
Fl_Text_Buffer* Search_buffer;
Fl_Text_Buffer* analysis_buffer;
Fl_Input* subject_info;
Fl_Input* selected_info;
Fl_Input* taken_time_info;
Fl_Window* export_win;
Fl_Window* analysis_win;
Fl_Window* search_win;

std::string Path = "./Artifacts/";
std::string DestDir;
std::wstring WDestDir;
std::wstring Analysis_Print_Logs;

bool is64bit = false;

namespace fs = std::filesystem;

bool Ntfs = false;      bool Evts = false;          bool BrowserHist = false;
bool Prefetch = false;  bool Recent = false;        bool RDPCache = false;
bool USB = false;       bool UserAssist = false;    bool MediaFile = false;
bool Memory = false;    bool DiskImage = false;     bool Powershell = false;
bool Sysinfo = false;

bool MD5 = true;        bool SHA1 = false;          bool SHA256 = false;

bool PC_Power;
bool Windows_Power;

// ȯ�溯�� ó�� �Լ�
std::wstring ExpandEnvironmentStrings(const std::wstring& path) {
    wchar_t expandedPath[MAX_PATH];
    DWORD size = ExpandEnvironmentStringsW(path.c_str(), expandedPath, MAX_PATH);
    if (size == 0 || size > MAX_PATH) {
        // ���� ó��
        return L"";
    }
    return std::wstring(expandedPath);
}

// ���丮 ũ�� Ȯ��
uintmax_t get_directory_size(const fs::path& path) {
    uintmax_t size = 0;
    for (auto& p : fs::recursive_directory_iterator(path)) {
        if (fs::is_regular_file(p)) {
            size += fs::file_size(p);
        }
    }
    return size;
}

// ���丮 ũ�� �� ������ ������ ���
void print_human_readable_size(uintmax_t size_in_bytes) {
    double size = static_cast<double>(size_in_bytes);

    std::string unit = "B";
    if (size >= 1024) {
        size /= 1024;
        unit = "KB";
    }
    if (size >= 1024) {
        size /= 1024;
        unit = "MB";
    }
    if (size >= 1024) {
        size /= 1024;
        unit = "GB";
    }

    std::cout << std::fixed << std::setprecision(2) << "Total size: " << size << " " << unit << std::endl;
}

// MD5 �ؽ� ��� �Լ�
std::string CalculateMD5(const std::wstring& filePath) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[16];
    DWORD cbHash = 0;
    // Initialize Cryptographic Service Provider (CSP)
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return "";
    }
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    {
        std::ifstream file(filePath, std::ios::binary);
        char buffer[4096];
        while (file.read(buffer, sizeof(buffer))) {
            if (!CryptHashData(hHash, (BYTE*)buffer, sizeof(buffer), 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return "";
            }
        }
        // Handle any bytes left in the buffer
        if (!CryptHashData(hHash, (BYTE*)buffer, file.gcount(), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
    }
    cbHash = sizeof(rgbHash);
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        std::string hash;
        for (DWORD i = 0; i < cbHash; i++) {
            char tmp[3] = { 0 };
            sprintf_s(tmp, sizeof(tmp), "%02x", rgbHash[i]);
            hash += tmp;
        }
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return hash;
    }
    else {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
}

// SHA1 �ؽ� ��� �Լ�
std::string CalculateSHA1(const std::wstring& filePath) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[20];
    DWORD cbHash = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return "";
    }

    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    std::ifstream file(filePath, std::ios::binary);
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        if (!CryptHashData(hHash, (BYTE*)buffer, sizeof(buffer), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
    }

    if (!CryptHashData(hHash, (BYTE*)buffer, file.gcount(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    cbHash = sizeof(rgbHash);
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        std::string hash;
        for (DWORD i = 0; i < cbHash; i++) {
            char tmp[3] = { 0 };
            sprintf_s(tmp, sizeof(tmp), "%02x", rgbHash[i]);
            hash += tmp;
        }
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return hash;
    }
    else {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
}

// SHA256 �ؽ� ��� �Լ�
std::string CalculateSHA256(const std::wstring& filePath) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[32];
    DWORD cbHash = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return "";
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    std::ifstream file(filePath, std::ios::binary);
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        if (!CryptHashData(hHash, (BYTE*)buffer, sizeof(buffer), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
    }

    if (!CryptHashData(hHash, (BYTE*)buffer, file.gcount(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    cbHash = sizeof(rgbHash);
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        std::string hash;
        for (DWORD i = 0; i < cbHash; i++) {
            char tmp[3] = { 0 };
            sprintf_s(tmp, sizeof(tmp), "%02x", rgbHash[i]);
            hash += tmp;
        }
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return hash;
    }
    else {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
}

bool ReadUSBRegistry() {
    HKEY hKey;
    LONG openStatus = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", 0, KEY_READ, &hKey);

    if (openStatus != ERROR_SUCCESS) {
        std::cerr << "Error opening registry key: " << openStatus << std::endl;
        return false;
    }

    DWORD dwIndex = 0;
    wchar_t lpName[255];
    DWORD lpcName = 255;
    FILETIME lpftLastWriteTime;

    while (RegEnumKeyExW(hKey, dwIndex, lpName, &lpcName, NULL, NULL, NULL, &lpftLastWriteTime) == ERROR_SUCCESS) {
        std::wcout << L"USB Device: " << lpName << std::endl;

        // TODO: �߰������� ���� Ű�� ��� �� ���� ������ ����

        dwIndex++;
        lpcName = 255;  // ���� ũ�� �ʱ�ȭ
    }

    RegCloseKey(hKey);
    return true;
}

// ���� �ؽ� ����� ���� �Լ�
bool CalculateHashesForFiles(const std::wstring& destDir, const std::wstring& extension) {
    // �ؽ� ������ �����ϰų� ����
    std::wofstream hashFile(destDir + L"\\calculated_hash.txt");
    if (!hashFile.good()) {
        std::wcerr << L"Failed to open or create hash file." << std::endl;
        return false;
    }

    try {
        for (const auto& entry : std::filesystem::directory_iterator(destDir)) {
            if (entry.path().extension() == extension || extension == L".*") {
                std::wstring filePath = entry.path().wstring();

                std::string hash;
                if (MD5)                hash = CalculateMD5(filePath);
                else if (SHA1)          hash = CalculateSHA1(filePath);
                else if (SHA256)        hash = CalculateSHA256(filePath);

                if (hash.empty()) {
                    std::wcerr << L"Failed to calculate hash for file: " << entry.path().filename().wstring() << std::endl;
                    hashFile.close();
                    return false;
                }

                hashFile << entry.path().filename().wstring() << L": " << std::wstring(hash.begin(), hash.end()) << std::endl;
            }
        }
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::wcerr << "Filesystem error: " << e.what() << std::endl;
        hashFile.close();
        return false;
    }
    catch (const std::exception& e) {
        std::wcerr << "An exception occurred: " << e.what() << std::endl;
        hashFile.close();
        return false;
    }

    hashFile.close();
    return true;
}


// ���� ���� �� �ؽ� ��� �Լ�
bool CopyAndHashFiles(const std::wstring& sourceDir, const std::wstring& destDir, const std::wstring& extension) {
    // �ؽ� ������ �����ϰų� ����
    std::wofstream hashFile(destDir + L"\\calculated_hash.txt");
    if (!hashFile.good()) {
        std::wcerr << L"Failed to open or create hash file." << std::endl;
        return false;
    }

    try {
        for (const auto& entry : std::filesystem::directory_iterator(sourceDir)) {
            if (entry.path().extension() == extension || extension == L".*") {
                std::wstring destPath = destDir + L"\\" + entry.path().filename().wstring();

                if (!CopyFileW(entry.path().c_str(), destPath.c_str(), FALSE)) {
                    std::cerr << "Error copying file: " << GetLastError() << std::endl;
                    hashFile.close();
                    return false;
                }
                std::string hash;
                if (MD5)                hash = CalculateMD5(destPath);
                else if (SHA1)          hash = CalculateSHA1(destPath);
                else if (SHA256)        hash = CalculateSHA256(destPath);
                if (hash.empty()) {
                    std::wcerr << L"Failed to calculate hash for file: " << entry.path().filename().wstring() << std::endl;
                    hashFile.close();
                    return false;
                }
                hashFile << entry.path().filename().wstring() << L": " << std::wstring(hash.begin(), hash.end()) << std::endl;
            }
        }
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::wcerr << "Filesystem error: " << e.what() << std::endl;
        hashFile.close();
        return false;
    }
    catch (const std::exception& e) {
        std::wcerr << "An exception occurred: " << e.what() << std::endl;
        hashFile.close();
        return false;
    }

    hashFile.close();
    return true;
}

//---------------------------------------------------------------------------------------------------------------
//Analysis ��� �߰� �κ� ---------------------------------------------------------------------------------------
//�˻��� ���Ϸ� ����
void SaveEventToFile(const wchar_t* content, const wchar_t* filename) {
    if (filename != NULL && content != NULL) {
        FILE* file;
        errno_t err = _wfopen_s(&file, filename, L"a");
        if (err == 0 && file != NULL) {
            fwprintf(file, L"%s\n", content);
            fclose(file);
        }
        else {
            wprintf(L"Failed to open file %s\n", filename);
        }
    }
    else {
        wprintf(L"Filename or content is NULL.\n");
    }
}


//�̺�Ʈ ������ ó��(xml�� ��ȯ) �Լ�
void ProcessEvent(EVT_HANDLE hEvent, const wchar_t* filename)
{
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    LPWSTR pRenderedContent = NULL;

    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
    {
        if (ERROR_INSUFFICIENT_BUFFER == GetLastError())
        {
            dwBufferSize = dwBufferUsed;
            pRenderedContent = (LPWSTR)malloc(dwBufferSize);
            if (pRenderedContent)
            {
                EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
            }
        }
        else
        {
            //wprintf(L"EvtRender failed with %lu\n", GetLastError());
            std::string error_message = "EvtRender failed with error code " + std::to_string(GetLastError());
            analysis_buffer->append(error_message.c_str());

            if (pRenderedContent)
                free(pRenderedContent);
            return;
        }
    }

    //wprintf(L"\n\n%s\n\n", pRenderedContent);
    SaveEventToFile(pRenderedContent, filename);

    if (pRenderedContent)
        free(pRenderedContent);
}

std::string WStringToString(const std::wstring& wstr)
{
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

void QueryMultiplePaths(const std::vector<std::wstring>& paths, const wchar_t* query, DWORD flags, const wchar_t* filename)
{
    for (const auto& path : paths) {
        //wprintf(L"Querying path: %s\n", path.c_str());

        EVT_HANDLE hResults = EvtQuery(NULL, path.c_str(), query, flags);

        if (NULL == hResults) {
            //wprintf(L"EvtQuery failed with %lu for path %s\n", GetLastError(), path.c_str());
            continue; // ���� ��η� ����
        }

        // �̺�Ʈ ó��
        DWORD dwReturned = 0;
        EVT_HANDLE hEvents[10];
        while (EvtNext(hResults, 10, hEvents, INFINITE, 0, &dwReturned))
        {
            for (DWORD i = 0; i < dwReturned; i++)
            {
                ProcessEvent(hEvents[i], filename);  // filename�� �߰��� ����
                EvtClose(hEvents[i]);
            }
        }

        DWORD status = GetLastError();
        if (ERROR_NO_MORE_ITEMS != status) {
            //wprintf(L"EvtNext failed with %lu for path %s\n", GetLastError(), path.c_str());
        }

        EvtClose(hResults);
    }
}

void Search_PC_Power() {
    //���� �̸� �� ��� ����.
    const wchar_t* filename = L"./Artifacts/Search_PC_Power.txt";

    // ��� �Է�

    //ä��(System, Application, Security ��... )
    std::vector<std::wstring> logPathsChannel = {
        L"System",
        L"Application",
        L"Security"
        // ... �߰� ä�� ���
    };

    //������Ʈ�� ���̺� �� �̺�Ʈ �α�? ���� ���...
    std::vector<std::wstring> logPathsFile = {
        // ... �߰� ���� ���
    };
    QueryMultiplePaths(logPathsChannel, L"*[System[(EventID=12)]]", EvtQueryChannelPath, filename);
    QueryMultiplePaths(logPathsChannel, L"*[System[(EventID=13)]]", EvtQueryChannelPath, filename);
    QueryMultiplePaths(logPathsFile, L"*[System[(EventID=12)]]", EvtQueryFilePath, filename);
    QueryMultiplePaths(logPathsFile, L"*[System[(EventID=13)]]", EvtQueryFilePath, filename);
}

void Search_Windows_Power() {
    //���� �̸� ����.
    const wchar_t* filename = L"./Artifacts/Search_Windows_Power.txt";

    // ��� �Է�

    //ä��(System, Application, Security ��... )
    std::vector<std::wstring> logPathsChannel = {
        L"System",
        L"Application",
        L"Security"
        // ... �߰� ä�� ���
    };

    //������Ʈ�� ���̺� �� �̺�Ʈ �α�? ���� ���...
    std::vector<std::wstring> logPathsFile = {
        // ... �߰� ���� ���
    };
    QueryMultiplePaths(logPathsChannel, L"*[System[(EventID=100)]]", EvtQueryChannelPath, filename);
    QueryMultiplePaths(logPathsChannel, L"*[System[(EventID=200)]]", EvtQueryChannelPath, filename);
    QueryMultiplePaths(logPathsFile, L"*[System[(EventID=100)]]", EvtQueryFilePath, filename);
    QueryMultiplePaths(logPathsFile, L"*[System[(EventID=200)]]", EvtQueryFilePath, filename);
}

// ������ MAC time ������ �����ϴ� �Լ�
void GetFileTimeInfo(const std::wstring& filePath, std::ofstream& outFile) {
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    FILETIME creationTime, lastAccessTime, lastWriteTime;
    SYSTEMTIME sysCreationTime, sysLastAccessTime, sysLastWriteTime;

    if (!GetFileTime(hFile, &creationTime, &lastAccessTime, &lastWriteTime)) {
        CloseHandle(hFile);
        return;
    }

    // Convert FILETIME to SYSTEMTIME
    FileTimeToSystemTime(&creationTime, &sysCreationTime);
    FileTimeToSystemTime(&lastAccessTime, &sysLastAccessTime);
    FileTimeToSystemTime(&lastWriteTime, &sysLastWriteTime);

    outFile << "File: " << std::string(filePath.begin(), filePath.end()) << std::endl;

    outFile << "Creation Time: " << sysCreationTime.wYear << "-"
        << std::setw(2) << std::setfill('0') << sysCreationTime.wMonth << "-"
        << std::setw(2) << std::setfill('0') << sysCreationTime.wDay << " "
        << std::setw(2) << std::setfill('0') << sysCreationTime.wHour << ":"
        << std::setw(2) << std::setfill('0') << sysCreationTime.wMinute << ":"
        << std::setw(2) << std::setfill('0') << sysCreationTime.wSecond << std::endl;

    outFile << "Last Access Time: " << sysLastAccessTime.wYear << "-"
        << std::setw(2) << std::setfill('0') << sysLastAccessTime.wMonth << "-"
        << std::setw(2) << std::setfill('0') << sysLastAccessTime.wDay << " "
        << std::setw(2) << std::setfill('0') << sysLastAccessTime.wHour << ":"
        << std::setw(2) << std::setfill('0') << sysLastAccessTime.wMinute << ":"
        << std::setw(2) << std::setfill('0') << sysLastAccessTime.wSecond << std::endl;

    outFile << "Last Write Time: " << sysLastWriteTime.wYear << "-"
        << std::setw(2) << std::setfill('0') << sysLastWriteTime.wMonth << "-"
        << std::setw(2) << std::setfill('0') << sysLastWriteTime.wDay << " "
        << std::setw(2) << std::setfill('0') << sysLastWriteTime.wHour << ":"
        << std::setw(2) << std::setfill('0') << sysLastWriteTime.wMinute << ":"
        << std::setw(2) << std::setfill('0') << sysLastWriteTime.wSecond << std::endl;

    outFile << "------------------------" << std::endl;

    CloseHandle(hFile);
}


// ���͸� ���� ��� ������ ������� GetFileTimeInfo �Լ��� ȣ��
void ProcessDirectory(const std::wstring& dirPath, std::ofstream& outFile) {
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW((dirPath + L"\\*").c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::cerr << "Invalid directory path." << std::endl;
        return;
    }

    do {
        const std::wstring fileOrDirName = findFileData.cFileName;
        const std::wstring fullFileName = dirPath + L"\\" + fileOrDirName;

        if (fileOrDirName != L"." && fileOrDirName != L"..") {
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                ProcessDirectory(fullFileName, outFile);
            }
            else {
                GetFileTimeInfo(fullFileName, outFile);
            }
        }
    } while (FindNextFileW(hFind, &findFileData) != 0);
    FindClose(hFind);
}

//---------------------------------------------------------------------------------------------------------------
//export ��ư ���� ��� ��!! ++ save ��ư ������ �� -------------------------------------------------------------
void save_Data(Fl_Widget* w, void* data) {
    void** widgets = (void**)data;
    Fl_Output* date_output = (Fl_Output*)widgets[0];
    Fl_Output* investigator_output = (Fl_Output*)widgets[1];

    std::string date = date_output->value();
    std::string investigator = investigator_output->value();
    std::string subject = subject_info->value();
    std::string selected = selected_info->value();

    // info_.txt �� ���� ����
    std::ofstream infoFile(Path + "info_.txt");
    infoFile << "Date: " << date << "\n";
    infoFile << "Investigator: " << investigator << "\n";
    infoFile << "Subject: " << subject << "\n";
    infoFile << "Selected Targets: " << selected << "\n";
    infoFile.close();
    SetFileAttributes(L"./Artifacts/info_.txt", FILE_ATTRIBUTE_READONLY);

    // üũ�� �� ��Ƽ��Ʈ�� �� ��Ƽ��Ʈ�� �̸����� ���� ����
    if (Ntfs) {
        std::system("Achoir\\Achoir.exe /ini:Achoir\\NTFS_Artifact.ACQ");
        CalculateHashesForFiles(L".\\Artifacts\\NTFS_Artifact", L".*");

        std::wstring dirPath = L".\\Artifacts\\NTFS_Artifact";
        std::ofstream outFile(".\\Artifacts\\NTFS_Artifact\\MAC_times.txt");

        ProcessDirectory(dirPath, outFile);

        outFile.close();
    }

    if (Evts) {
        std::wstring eventLogSourceDir = L"C:\\Windows\\System32\\winevt\\Logs";
        std::system("mkdir Artifacts\\WinEvts");
        std::wstring eventLogDestDir = L".\\Artifacts\\WinEvts";

        CopyAndHashFiles(eventLogSourceDir, eventLogDestDir, L".evtx");

        std::ofstream outFile(".\\Artifacts\\WinEvts\\MAC_times.txt");

        ProcessDirectory(eventLogSourceDir, outFile);

        outFile.close();
    }

    if (Prefetch) {
        std::wstring prefetchSourceDir = L"C:\\Windows\\Prefetch";
        std::system("mkdir Artifacts\\Prefetch");
        std::wstring prefetchDestDir = L".\\Artifacts\\Prefetch";

        CopyAndHashFiles(prefetchSourceDir, prefetchDestDir, L".pf");

        std::ofstream outFile(".\\Artifacts\\Prefetch\\MAC_times.txt");

        ProcessDirectory(prefetchSourceDir, outFile);

        outFile.close();
    }

    if (BrowserHist) {
        std::system("Achoir\\Achoir.exe /ini:Achoir\\BrowserHistory.ACQ");

        std::wstring ChromeHistSrcDir = L"%localappdata%\\Google\\Chrome\\User Data\\Cache";
        ChromeHistSrcDir = ExpandEnvironmentStrings(ChromeHistSrcDir);
        std::wstring ChromeHistDstDir = L".\\Artifacts\\Brw\\Chrome";

        CopyAndHashFiles(ChromeHistSrcDir, ChromeHistDstDir, L".*");

        std::ofstream outFile(".\\Artifacts\\Brw\\MAC_times.txt");

        ProcessDirectory(ChromeHistDstDir, outFile);

        outFile.close();
    }

    if (Recent) {
        std::wstring lnkSourceDir = L"%APPDATA%\\Microsoft\\Windows\\Recent";
        lnkSourceDir = ExpandEnvironmentStrings(lnkSourceDir);
        std::system("mkdir Artifacts\\Recent");
        std::wstring lnkDestDir = L".\\Artifacts\\Recent";

        CopyAndHashFiles(lnkSourceDir, lnkDestDir, L".lnk");

        std::ofstream outFile(".\\Artifacts\\Recent\\MAC_times.txt");

        ProcessDirectory(lnkDestDir, outFile);

        outFile.close();
    }

    if (RDPCache) {
        std::wstring RDPSourceDir = L"%LOCALAPPDATA%\\Microsoft\\Terminal Sever Client\\Cache";
        RDPSourceDir = ExpandEnvironmentStrings(RDPSourceDir);
        std::system("mkdir \"Artifacts\\RDP Cache\"");
        std::wstring RDPDestDir = L".\\Artifacts\\RDP Cache";

        CopyAndHashFiles(RDPSourceDir, RDPDestDir, L".*");

        std::ofstream outFile(".\\Artifcats\\RDP Cache\\MAC_times.txt");

        ProcessDirectory(RDPDestDir, outFile);

        outFile.close();
    }

    if (USB) {
        ReadUSBRegistry();
    }

    if (UserAssist) {
        std::system("Achoir\\Achoir.exe /ini:Achoir\\UserAssist.ACQ");
    }

    if (Memory) {
        std::system("Achoir\\Achoir.exe /ini:Achoir\\MemoryDmp.ACQ");
    }

    if (Powershell) {
        std::wstring PowerShellSrcDir = L"%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine";
        PowerShellSrcDir = ExpandEnvironmentStrings(PowerShellSrcDir);
        std::system("mkdir Artifacts\\PSHistory");
        std::wstring PowerShellDstDir = L".\\Artifacts\\PSHistory";

        CopyAndHashFiles(PowerShellSrcDir, PowerShellDstDir, L".*");

        std::ofstream outFile(".\\Artifcats\\PSHistory\\MAC_times.txt");

        ProcessDirectory(PowerShellDstDir, outFile);

        outFile.close();
    }

    if (Sysinfo) {
        std::system("Achoir\\Achoir.exe /ini:Achoir\\Sysinfo.ACQ");
    }

    //----------------------------------
    /*
    if (PC_Power) {
        std::system("Achoir\\Achoir.exe /ini:Achoir\\MemoryDmp.ACQ");
    }
    if (Windows_Power) {
        std::system("Achoir\\Achoir.exe /ini:Achoir\\MemoryDmp.ACQ");
    }
    */
    CalculateHashesForFiles(L".\\Artifacts\\Reg", L".*");
    CalculateHashesForFiles(L".\\Artifacts\\RBin", L".*");

    std::ofstream outFile(".\\Artifacts\\Reg\\MAC_times.txt");
    ProcessDirectory(L".\\Artifacts\\Reg", outFile);
    outFile.close();

    std::ofstream outFile2(".\\Artifacts\\RBin\\MAC_times.txt");
    ProcessDirectory(L".\\Artifacts\\RBin", outFile);
    outFile2.close();

    //----- ZIP | 7z ���� ��� : 1. ��� ���� ��� -----//
    std::wstring WorkingDir = L".\\Artifacts";

    // �׽�Ʈ ��� : currentDir ���� ���
    std::wcout << L"[+] Current Directory: " << WorkingDir << std::endl;

    // Artifacts ������ �ִ� ��� ������ �� ���� ������ Artifacts.zip ���Ϸ� �����ϴ� ���
    // Ex) bandizip.exe c zip���ϰ��/zip�����̸�.zip ������_���/ ������_�߰����/
    // C : (���� ���� ������ ����) date : (���� ������ ��θ� ���� �ý��� �ð��� ����)
    // ���� ������ ���� Ȯ���� : zip, zipx, exe, tar, tgz, lzh, iso, 7z, gz, xz

    try {
        // 2. ��� ����
        fs::path path_to_check = WorkingDir;

        // 3. ����� ��ũ ��뷮 ���
        uintmax_t size_in_bytes = get_directory_size(path_to_check);

        // �뷮�� �б� ���� ���·� ���
        print_human_readable_size(size_in_bytes);

        // 4. �뷮�� 1GB �̸����� Ȯ��
        if (static_cast<double>(size_in_bytes) < 1024.0 * 1024.0 * 1024.0) {
            // 4-1. B Ŀ�ǵ� �ۼ�
            std::string command_1 = "Bandizip\\Bandizip.exe c -date Artifacts_%Y-%m-%d_%H-%M-%S.zip Artifacts";
            // �׽�Ʈ ��� : Commnad_1 Line �� ���
            std::cout << "[+] Command Line: " << command_1 << std::endl;
            // 4-2. ����
            int result = system(command_1.c_str());
        }
        else {
            // 5. C Ŀ�ǵ� �ۼ�
            std::string command_2 = "Bandizip\\Bandizip.exe c -date Artifacts_%Y-%m-%d_%H-%M-%S.7z Artifacts";
            // �׽�Ʈ ��� : Commnad_2 Line �� ���
            std::cout << "[+] Command Line: " << command_2 << std::endl;
            // 5-1. ����
            int result = system(command_2.c_str());
        }
    }
    // ���� ���
    catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
    }

    // ACQ-IR �۾� ���� ����
    system("for /d %a in (ACQ-IR*) do rd /s /q \"%a\"");

    //���� �� �Ǹ� save â �Ⱥ��̰�
    if (export_win) {
        export_win->hide();
    }
}

// Callback for 'Export' button - ���� ���� ���
void export_Data(Fl_Widget* w, void* data) {
    export_win = new Fl_Window(350, 180, "Additional Information");

    subject_info = new Fl_Input(100, 10, 200, 30, "subject_info:");
    selected_info = new Fl_Input(100, 50, 200, 30, "selected_info:");

    Fl_Button* save_button = new Fl_Button(150, 130, 80, 30, "Save");
    save_button->callback(save_Data, data);

    export_win->end();
    export_win->show();

}

//---------------------------------------------------------------------------------------------------------------
//üũ �ڽ� ���� �κ�--------------------------------------------------------------------------------------------
//üũ�ڽ� Ŭ�� �� ���� ��� ��ȯ
void updateTextDisplay(Fl_Widget* w, void* data) {
    Fl_Check_Button* button = (Fl_Check_Button*)w;
    const char* label = button->label();

    if (button->value()) {  // if checked
        // üũ�ڽ� �� Ȯ���� ���� ó��
        if (label == "System Files: NTFS Artifact, Registry, $Recycle.bin, ...")            Ntfs = true;
        else if (label == "Event Log")          Evts = true;
        else if (label == "Browser History")    BrowserHist = true;
        else if (label == "Windows Prefetch")   Prefetch = true;
        else if (label == "lnk File")           Recent = true;
        else if (label == "RDP Cache")          RDPCache = true;
        else if (label == "USB")                USB = true;
        else if (label == "UserAssist Info")    UserAssist = true;
        else if (label == "Memory Full Dump")   Memory = true;
        else if (label == "PowerShell Logs")    Powershell = true;
        else if (label == "Environment Var, IP Info, Connection Info, Patch List, ...") Sysinfo = true;
    }
    else {
        if (label == "System Files: NTFS Artifact, Registry, $Recycle.bin, ...")            Ntfs = false;
        else if (label == "Event Log")          Evts = false;
        else if (label == "Browser History")    BrowserHist = false;
        else if (label == "Windows Prefetch")   Prefetch = false;
        else if (label == "lnk File")           Recent = false;
        else if (label == "RDP Cache")          RDPCache = false;
        else if (label == "USB")                USB = false;
        else if (label == "UserAssist Info")    UserAssist = false;
        else if (label == "Memory Full Dump")   Memory = false;
        else if (label == "PowerShell Logs")    Powershell = false;
        else if (label == "Environment Var, IP Info, Connection Info, Patch List, ...") Sysinfo = false;
    }
}

// Callback for 'Input' button ....main�Լ����� ���� outputâ�� ������ �ִ�. Input ��ư�� ������ Inputâ�� �������� Output â�� ��Ÿ������  
void transferInputToOutput(Fl_Widget* w, void* data) {
    Fl_Input* date_input = (Fl_Input*)(((void**)data)[0]);
    Fl_Input* investigator_input = (Fl_Input*)(((void**)data)[1]);
    Fl_Output* date_output = (Fl_Output*)(((void**)data)[2]);
    Fl_Output* investigator_output = (Fl_Output*)(((void**)data)[3]);

    date_output->value(date_input->value());
    investigator_output->value(investigator_input->value());

    date_input->hide();
    investigator_input->hide();

    date_output->show();
    investigator_output->show();

    date_output->redraw();
    investigator_output->redraw();

    //��Ƽ��Ʈ ���� �� ���� ����.!!
    //Copy_eventlog_Filesave();
}

void Search_PC_Power_CB(Fl_Widget* w, void* data) {
    Fl_Check_Button* checkbox = (Fl_Check_Button*)w;
    if (checkbox->value()) {
        Search_PC_Power();  // üũ�ڽ��� üũ�Ǹ� �Լ��� ȣ���մϴ�.
    }
}

void Search_Windows_Power_CB(Fl_Widget* w, void* data) {
    Fl_Check_Button* checkbox = (Fl_Check_Button*)w;
    if (checkbox->value()) {
        Search_Windows_Power();  // üũ�ڽ��� üũ�Ǹ� �Լ��� ȣ���մϴ�.
    }
}

void hash_choice_cb(Fl_Widget* w, void* data) {
    Fl_Choice* choice = (Fl_Choice*)w;
    const Fl_Menu_Item& item = choice->menu()[choice->value()];

    if (strcmp(item.label(), "MD5") == 0) {
        MD5 = true;     SHA1 = false;       SHA256 = false;
    }
    else if (strcmp(item.label(), "SHA-1") == 0) {
        MD5 = false;    SHA1 = true;        SHA256 = false;
    }
    else if (strcmp(item.label(), "SHA-256") == 0) {
        MD5 = false;    SHA1 = false;       SHA256 = true;
    }
}

//------------------------------------------------------------------------------------------
// Search �κ� �Լ�--------------------------------------------------------------------------
// ���� ������ �˻��ϴ� �Լ�
bool ProcessFile(const std::string& filePath, const std::string& query) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return false;
    }

    bool searchResultsFound = false;
    std::string line;
    std::string queryLower = query; // �˻�� �ҹ��ڷ� ��ȯ

    // ��� �˻�� �ҹ��ڷ� ��ȯ
    std::transform(queryLower.begin(), queryLower.end(), queryLower.begin(), ::tolower);

    while (std::getline(file, line)) {
        std::string lineLower = line; // ���� ������ �ҹ��ڷ� ��ȯ

        // ���� ������ �ҹ��ڷ� ��ȯ�Ͽ� �˻�
        std::transform(lineLower.begin(), lineLower.end(), lineLower.begin(), ::tolower);

        if (lineLower.find(queryLower) != std::string::npos) {
            // �˻�� ���Ե� ���� ����� �߰�
            Search_buffer->append(("Found in file: " + filePath + "\n").c_str());
            Search_buffer->append(("Line: " + line + "\n\n").c_str());
            searchResultsFound = true;
        }
    }

    if (file.fail() && !file.eof()) {
        std::cerr << "Error occurred while reading the file: " << filePath << std::endl;
    }

    file.close();
    return searchResultsFound;
}

bool ProcessDirectory(const std::string& path, const std::string& query, const std::string& fileExtension) {
    bool searchResultsFound = false;
    std::string queryLower = query;

    std::transform(queryLower.begin(), queryLower.end(), queryLower.begin(), ::tolower);

    for (const auto& entry : fs::directory_iterator(path)) {
        // ������ ��� ó��
        if (entry.is_regular_file()) {
            std::string filePath = entry.path().string();

            // ���� �̸��� ���Ͽ� �˻�
            std::string fileName = entry.path().filename().string();
            std::string fileNameLower = fileName;
            std::transform(fileNameLower.begin(), fileNameLower.end(), fileNameLower.begin(), ::tolower);

            if (fileNameLower.find(queryLower) != std::string::npos) {
                Search_buffer->append(("Found in file: " + filePath + "\n").c_str());
                searchResultsFound = true;
            }

            // ���� Ȯ���ڸ� ���Ͽ� �˻�
            if (fileExtension.empty() || fs::path(filePath).extension() == fileExtension) {
                searchResultsFound |= ProcessFile(filePath, query);
            }
        }
        // ���丮�� ��� ó��
        else if (entry.is_directory()) {
            std::string dirName = entry.path().filename().string();
            std::string dirNameLower = dirName;

            // "Memory Full Dump" ���丮 ����ó�� 
            if (dirName == "MemDump") {
                continue;
            }

            std::transform(dirNameLower.begin(), dirNameLower.end(), dirNameLower.begin(), ::tolower);

            // �˻�� ���丮 �̸��� ���ԵǴ��� Ȯ��
            if (dirNameLower.find(queryLower) != std::string::npos) {
                Search_buffer->append(("���丮 �߰�: " + entry.path().string() + "\n").c_str());
                searchResultsFound = true;
            }

            // ���丮 ���� ���� �� ���� ���丮 �˻�
            searchResultsFound |= ProcessDirectory(entry.path().string(), query, fileExtension);
        }
    }

    return searchResultsFound;
}

// �˻� ���
bool search_in_artifacts(Fl_Widget* widget, void* data) {
    // Null Check
    if (data == nullptr) {
        std::cerr << "Data is null." << std::endl;
        return false;
    }

    Fl_Widget* widget_ptr = static_cast<Fl_Widget*>(data);
    if (widget_ptr == nullptr) {
        std::cerr << "Static cast failed: data could not be cast to Fl_Widget*." << std::endl;
        return false;
    }

    Fl_Input* input = dynamic_cast<Fl_Input*>(widget_ptr);
    if (input == nullptr) {
        std::cerr << "Invalid type: data is not a Fl_Input*." << std::endl;
        return false;
    }

    if (Search_buffer == nullptr) {
        Search_buffer = new Fl_Text_Buffer();
    }

    const char* query = input->value();
    if (query == nullptr || strlen(query) == 0) {
        std::cerr << "Query is empty or invalid." << std::endl;
        return false;
    }

    if (search_win == nullptr) {
        search_win = new Fl_Window(350, 180, "Search Results");
        search_win->callback([](Fl_Widget*, void*) {
            // �˻� ��� â�� ���� �� Search_buffer �ʱ�ȭ
            if (Search_buffer != nullptr) {
                Search_buffer->text("");
            }
            if (search_win != nullptr) {
                search_win->hide(); // �˻� ��� â �����
            }
            });
    }

    std::string path = "./Artifacts/";

    if (!fs::exists(path)) {
        std::cerr << "Directory does not exist: " << path << std::endl;
        return false;
    }

    // Initialize searchResultsFound to false
    bool searchResultsFound = ProcessDirectory(path, query, "");

    // Check if search results were found
    if (!searchResultsFound) {
        Search_buffer->append("No search results found.");
    }

    search_win->end();
    search_win->show();

    return searchResultsFound;
}

// Search ��ư �ݹ� �Լ�
void search_button_callback(Fl_Widget* widget, void* data) {
    Fl_Input* search_input = static_cast<Fl_Input*>(data);
    if (search_input == nullptr) {
        std::cerr << "Invalid data." << std::endl;
        return;
    }

    bool searchResultsFound = search_in_artifacts(nullptr, search_input);

    if (searchResultsFound) {
        // �˻� ����� Search_buffer�� ����Ǿ����Ƿ�, �� ������ search_win�� ���
        search_win->begin();
        Fl_Text_Display* text_display = new Fl_Text_Display(10, 10, 330, 160);
        text_display->buffer(Search_buffer);
        search_win->end();
        search_win->show();
    }
    else {
        // �˻� ����� ���� �� �޽��� ǥ��
        search_win->begin();
        Fl_Box* no_results_box = new Fl_Box(10, 10, 330, 160, "No search results found.");
        no_results_box->align(FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
        search_win->end();
        search_win->show();
    }
}


//---------------------------------------------------------------------------------------------------------------
//�����Լ�------------------------------------------------------------------------------------------------------
int main() {
    // ��ǻ�� 32��Ʈ üũ
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);

    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
        si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) {
        is64bit = true;
    }


    //��ü â UI
    Fl_Window win(700, 450, "Artifacts_Collector");

    //����â_UI
    Fl_Input date_input(120, 30, 200, 30, "Date:");
    Fl_Input investigator_input(120, 90, 200, 30, "Investigator:");

    Fl_Output date_output(120, 30, 200, 30, "Date:");
    Fl_Output investigator_output(120, 90, 200, 30, "Investigator:");

    //üũ�ڽ�_UI
    Fl_Check_Button NTFS_CheckBox(10, 150, 400, 30, "System Files: NTFS Artifact, Registry, $Recycle.bin, ...");
    Fl_Check_Button eventLog_CheckBox(10, 180, 130, 30, "Event Log");
    Fl_Check_Button browserHistory_CheckBox(130, 180, 160, 30, "Browser History");
    Fl_Check_Button Prefetch_CheckBox(270, 180, 160, 30, "Windows Prefetch");
    Fl_Check_Button LNK_FILE_CheckBox(10, 210, 130, 30, "lnk File");
    Fl_Check_Button RDP_Cache_CheckBox(130, 210, 130, 30, "RDP Cache");
    Fl_Check_Button USB(270, 210, 100, 30, "USB");
    Fl_Check_Button UserAssist_CheckBox(10, 240, 160, 30, "UserAssist Info");
    Fl_Check_Button Powershell_CheckBox(270, 240, 160, 30, "PowerShell Logs");
    Fl_Check_Button Memory_CheckBox(10, 270, 160, 30, "Memory Full Dump");
    Fl_Check_Button System_Info_CheckBox(10, 300, 400, 30, "Environment Var, IP Info, Connection Info, Patch List, ...");

    Fl_Choice hash_choice(500, 140, 120, 25, "Hash Algorithm:");
    Fl_Menu_Item hash_menu[] = {
        {"MD5", 0, 0, 0},
        {"SHA-1", 0, 0, 0},
        {"SHA-256", 0, 0, 0},
        {0}
    };
    // �ؽ� �˰��� ���� �޴�
    hash_choice.menu(hash_menu);
    hash_choice.callback(hash_choice_cb); // �ݹ� �Լ� ����

    //Fl_Button Disk_Imaging_CheckBox(120, 300, 400, 30, "Disk Imaging (Warning: Target Disk will be Overwritten");

    //üũ�ڽ� ���� ��� â
    //Fl_Text_Display text_display(120, 350, 400, 200);

    //üũ�ڽ� �κ� ����
    NTFS_CheckBox.callback(updateTextDisplay);
    eventLog_CheckBox.callback(updateTextDisplay);
    browserHistory_CheckBox.callback(updateTextDisplay);
    Prefetch_CheckBox.callback(updateTextDisplay);
    LNK_FILE_CheckBox.callback(updateTextDisplay);
    RDP_Cache_CheckBox.callback(updateTextDisplay);
    USB.callback(updateTextDisplay);
    UserAssist_CheckBox.callback(updateTextDisplay);
    Powershell_CheckBox.callback(updateTextDisplay);
    Memory_CheckBox.callback(updateTextDisplay);
    System_Info_CheckBox.callback(updateTextDisplay);

    //���� â ���� �� ��� ����
    date_output.color(FL_LIGHT2);
    investigator_output.color(FL_LIGHT2);
    date_output.textcolor(FL_GRAY);
    investigator_output.textcolor(FL_GRAY);
    date_output.hide();
    investigator_output.hide();

    //Input ��ư 
    void* widgets[] = { &date_input, &investigator_input, &date_output, &investigator_output };
    Fl_Button Input_button(350, 90, 80, 30, "Input");
    Input_button.callback(transferInputToOutput, widgets);

    //export ��ư
    void* exportWidgets[] = { &date_output, &investigator_output };
    Fl_Button Export_button(130, 330, 100, 30, "Export");
    Export_button.callback(export_Data, exportWidgets);

    // "Details" �� �߰�
    Fl_Box details_label(500, 30, 160, 30, "According to Event ID");

    // "Search_PC_Power" üũ�ڽ� �߰�
    Fl_Check_Button Search_PC_Power_CheckBox(500, 70, 200, 30, "Search_PC_Power");
    Search_PC_Power_CheckBox.callback(Search_PC_Power_CB);

    // "Search_PC_Power" üũ�ڽ� �߰�
    Fl_Check_Button Search_Windows_Power_CheckBox(500, 100, 200, 30, "Search_Windows_Power");
    Search_Windows_Power_CheckBox.callback(Search_Windows_Power_CB);


    // Search �κ�
    Fl_Input search_input(130, 380, 200, 30, "Search:");
    Fl_Button search_button(350, 380, 80, 30, "Search");
    search_button.callback(search_button_callback, &search_input);

    win.end();
    win.show();

    return Fl::run();
}