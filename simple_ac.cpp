#include "simple_ac.h"

bool simple_ac::is_memory_modified(const int* address, int expected_value)
{
    int value = *address;
    return value != expected_value;
}

bool simple_ac::is_signature_detected(const uint8_t* address, size_t signature_size)
{
    for (size_t i = 0; i < signature_size; i++)
    {
        if (address[i] != signatures::cheat_signature[i])
        {
            return false;
        }
    }
    return true;
}

bool simple_ac::is_cheating_process_running()
{
    DWORD process_ids[1024];
    DWORD bytes_returned;
    if (EnumProcesses(process_ids, sizeof(process_ids), &bytes_returned))
    {
        DWORD num_processes = bytes_returned / sizeof(DWORD);

        for (DWORD i = 0; i < num_processes; i++)
        {
            HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_ids[i]);
            if (h_process)
            {
                char process_name[MAX_PATH];
                if (GetModuleBaseName(h_process, NULL, process_name, sizeof(process_name)) > 0)
                {
                    std::string process_name_str(process_name);
                    for (const auto& cheating_process : cheating_processes)
                    {
                        if (process_name_str == cheating_process)
                        {
                            return true;
                        }
                    }
                }
                CloseHandle(h_process);
            }
        }
    }
    return false;
}

bool simple_ac::is_file_digitally_signed(const wchar_t* file_path)
{
    WINTRUST_FILE_INFO file_data = { 0 };
    file_data.cbStruct = sizeof(file_data);
    file_data.pcwszFilePath = file_path;
    file_data.hFile = NULL;
    file_data.pgKnownSubject = NULL;

    GUID guid_action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wintrust_data = { 0 };
    wintrust_data.cbStruct = sizeof(wintrust_data);
    wintrust_data.pPolicyCallbackData = NULL;
    wintrust_data.pSIPClientData = NULL;
    wintrust_data.dwUIChoice = WTD_UI_NONE;
    wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrust_data.dwUnionChoice = WTD_CHOICE_FILE;
    wintrust_data.dwStateAction = 0;
    wintrust_data.hWVTStateData = NULL;
    wintrust_data.pwszURLReference = NULL;
    wintrust_data.dwProvFlags = WTD_SAFER_FLAG;
    wintrust_data.dwUIContext = 0;

    LONG result = WinVerifyTrust(NULL, &guid_action, &wintrust_data);
    return result == ERROR_SUCCESS;
}

std::vector<std::string> simple_ac::get_mac_addresses()
{
    std::vector<std::string> mac_addresses;

    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        std::cout << "failed to initialize wsock\n";
        return mac_addresses;
    }

    ULONG buffer_size = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &buffer_size) == ERROR_BUFFER_OVERFLOW)
    {
        std::vector<BYTE> buffer(buffer_size, 0);
        PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(&buffer[0]);

        if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, addresses, &buffer_size) == NO_ERROR)
        {
            for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter != NULL; adapter = adapter->Next)
            {
                if (adapter->PhysicalAddressLength > 0)
                {
                    char mac_address[18] = { 0 };
                    for (ULONG i = 0; i < adapter->PhysicalAddressLength; i++)
                    {
                        sprintf_s(mac_address + i * 3, sizeof(mac_address) - i * 3, "%02X-", adapter->PhysicalAddress[i]); // change urself the operator to avoid overflow on x86 arch.
                    }
                    mac_addresses.push_back(mac_address);
                }
            }
        }
    }

    WSACleanup();

    return mac_addresses;
}