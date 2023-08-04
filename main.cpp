#include "simple_ac.h"

void simple_ac_function()
{
    const int secured_value = 9;

    while (true)
    {
        if (simple_ac::is_memory_modified(reinterpret_cast<int*>(0x9), secured_value))
            std::cout << "got caught - 0\n";

        const uint8_t* scan_start_address = reinterpret_cast<const uint8_t*>(0x9);
        const size_t scan_size = 0x9;

        for (size_t offset = 0; offset < scan_size - simple_ac::signatures::cheat_signature.size(); offset++)
        {
            const uint8_t* address_to_scan = scan_start_address + offset;
            if (simple_ac::is_signature_detected(address_to_scan, simple_ac::signatures::cheat_signature.size()))
                std::cout << "got caught - 1, address: " << reinterpret_cast<void*>(const_cast<uint8_t*>(address_to_scan)) << std::endl;
        }

        if (simple_ac::is_cheating_process_running())
            std::cout << "got caught - 2\n";

        const wchar_t* executable_path = L"greed\\code\\09.exe";
        if (!simple_ac::is_file_digitally_signed(executable_path))
            std::cout << "got caught - 3\n";

        std::vector<std::string> mac_addresses = simple_ac::get_mac_addresses();

        if (mac_addresses.empty())
            std::cout << "got caught - 4\n";

        Sleep(1000);
    }
}

int main()
{
    simple_ac_function();

    return 0;
}
