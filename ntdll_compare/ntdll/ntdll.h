#include "pch.h"

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG RELOC_FLAG32

namespace ntdll {

	BOOL read_file(const std::filesystem::path dllPath, std::vector<BYTE>* outVector)
	{
		std::ifstream file(dllPath, std::ios::binary | std::ios::ate);

		if (file.fail())
		{
			//printf_s("[-] Failed to open dll at %s for reading\n", dllPath.string().c_str());
			return FALSE;
		}

		// get length of file and set vector size
		size_t len = static_cast<size_t>(file.tellg());
		file.seekg(0, file.beg);
		outVector->resize(len);

		// read whole file into buffer
		file.read(reinterpret_cast<char*>(outVector->data()), len);
		file.close();

		return TRUE;
	}

	BYTE* disk_to_mem(const std::string& path)
	{

		IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
		IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
		IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
		BYTE* pTargetBase = nullptr;
		BYTE* pSrcData = 0;
		std::vector<BYTE> vSrcData;

		if (!read_file(path, &vSrcData))
		{
			printf("Failed to read file\n");
			return 0;
		}

		pSrcData = vSrcData.data();

		if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) { //"MZ"
			printf("Invalid file\n");
			return 0;
		}

		pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
		pOldOptHeader = &pOldNtHeader->OptionalHeader;
		pOldFileHeader = &pOldNtHeader->FileHeader;

		if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
			printf("Invalid platform\n");
			return 0;
		}

		pTargetBase = reinterpret_cast<BYTE*>(VirtualAlloc(0, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pTargetBase) {
			printf("Target process memory allocation failed (ex) 0x%X\n", GetLastError());
			return 0;
		}

		printf("Allocated at 0x%p\n", pTargetBase);

		//File header
		memcpy(pTargetBase, pSrcData, pOldNtHeader->OptionalHeader.SizeOfHeaders);

		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->SizeOfRawData) {
				memcpy(pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
			}
		}

		auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pTargetBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pTargetBase)->e_lfanew)->OptionalHeader;

		BYTE* LocationDelta = reinterpret_cast<BYTE*>(GetModuleHandleA(path.substr(path.find_last_of("\\") + 1, path.size()).data())) - pOpt->ImageBase;
		if (LocationDelta) {
			if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
				auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pTargetBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
				const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
				while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
					UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
					WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

					for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
						if (RELOC_FLAG(*pRelativeInfo)) {
							UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pTargetBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
							*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
						}
					}
					pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
				}
			}
		}

		return pTargetBase;
	}

	int ntdll_checking()
	{

		BYTE* ntdll_mapped = disk_to_mem("C:\\Windows\\SysWOW64\\ntdll.dll");
		HMODULE ntdll_local = GetModuleHandleA("ntdll.dll");

		PIMAGE_NT_HEADERS nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(ntdll_local) + (reinterpret_cast<PIMAGE_DOS_HEADER>(ntdll_local))->e_lfanew);
		PIMAGE_FILE_HEADER file_header = &nt_header->FileHeader;

		PIMAGE_EXPORT_DIRECTORY exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<BYTE*>(ntdll_local) + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		DWORD text_size = 0;

		PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);
		for (int i = 0; i != file_header->NumberOfSections; ++i, ++section_header) {
			if (section_header->SizeOfRawData) {
				if (strcmp(reinterpret_cast<char*>(section_header->Name), ".text") == 0)
				{
					text_size = section_header->Misc.VirtualSize;
					break;
				}
			}
		}

		BYTE** names = reinterpret_cast<BYTE**>(reinterpret_cast<int>(ntdll_local) + exports->AddressOfNames);
		while (true)
		{
			char buf[256];
			int j = 0;
			printf("Searching...\n");
			for (int i = 0; i < exports->NumberOfNames; i++)
			{
				std::sprintf(buf, "%s", reinterpret_cast<BYTE*>(ntdll_local) + reinterpret_cast<int>(names[i]));
				std::string name(buf);
				FARPROC export_address = GetProcAddress(ntdll_local, name.data());
				//printf("%p\n", export_address);
				if (reinterpret_cast<HMODULE>(export_address) < ntdll_local || reinterpret_cast<HMODULE>(export_address) > ntdll_local + text_size || name.compare(0, 2, "Nt") != 0 || name.compare(0, 2, "Zw") != 0 || name.compare(0, 3, "Rtl") != 0 || name.compare("NtProtectVirtualMemory") == 0)
					continue;
				void* address = ntdll_mapped + (reinterpret_cast<DWORD>(export_address) - reinterpret_cast<DWORD>(ntdll_local));
				if (memcmp(export_address, address, 15) != 0)
				{
					printf("Found patch at 0x%p (%s) (0x%p)\n", export_address, name.data(), address);
					j++;
				}
			}
			printf("Found a total of %i patches.\nDone searching...\n", j);
			std::cin.get();
		}
	}
};