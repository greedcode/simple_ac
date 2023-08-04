#pragma once
#include <iostream>
#include <winsock2.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <stdint.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#pragma comment(lib, "wintrust")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace simple_ac
{
	bool is_memory_modified(const int* address, int expected_value);

	bool is_signature_detected(const uint8_t* address, size_t signature_size);

	bool is_cheating_process_running();

	bool is_file_digitally_signed(const wchar_t* file_path);

	std::vector<std::string> get_mac_addresses();

	namespace signatures
	{
		inline const std::vector<uint8_t> cheat_signature = { 0x0, 0x0, 0x9 };
	}

	inline std::vector<std::string> cheating_processes = { "notepad.exe", "mspaint.exe" };
}