#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <Winver.h>

#pragma comment (lib, "version.lib")
#pragma comment (lib, "Advapi32.lib")

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef NTSTATUS(WINAPI *NTQUERYSYSTEMINFORMATION)(DWORD SystemInformationClass,
	PVOID SystemInformation,
	DWORD SystemInformationLength,
	PDWORD ReturnLength);


void lower(char *str)
{
	char *p = str;
	while (*p != '\0')
	{
		if ((*p >= 65) && (*p <= 90))
			*p = *p + 32;
		p++;
	}
	return;
}

 int __forceinline getversion(char *LibName)
{
	DWORD dwHandle, dwLen;
	UINT BufLen;
	LPTSTR lpData, lpBuffer;
	VS_FIXEDFILEINFO *pFileInfo;

	dwLen = GetFileVersionInfoSize(LibName, &dwHandle);
	printf("Library:              %s\n", LibName);
	if (!dwLen) {
		printf("VersionInfo           not found\n");
		return -1;
	}
	lpData = (LPTSTR)malloc(dwLen);
	if (!lpData) {
		perror("malloc");
		return -1;
	}
	if (!GetFileVersionInfo(LibName, dwHandle, dwLen, lpData)) {
		free(lpData);
		printf("VersionInfo:          not found\n");
		return -1;
	}

	char Dest[100];
	strcpy(Dest, "\\StringFileInfo\\040904E4\\");
	if (VerQueryValue(lpData, "\\VarFileInfo\\Translation", (LPVOID)&pFileInfo, (PUINT)&BufLen)) {
		sprintf(&Dest, "\\StringFileInfo\\%4.4X%4.4X\\", *(WORD *)pFileInfo, *((WORD *)pFileInfo + 1));
		if (!VerQueryValue(lpData, Dest, (LPVOID)&pFileInfo, (PUINT)&BufLen)) {
			strcpy(Dest, "\\StringFileInfo\\040904E4\\");
		}
	}
	DWORD dwStrFileInfoLen = strlen(Dest);
	strcat(Dest, "FileVersion"); printf("FileVersion: ");
	if (!VerQueryValue(lpData, Dest, (LPVOID)&lpBuffer, (PUINT)&BufLen))printf("not found\n");else printf("%s\n", lpBuffer);Dest[dwStrFileInfoLen] = '\0';
	strcat(Dest, "ProductName"); printf("ProductName: ");
	if (!VerQueryValue(lpData, Dest, (LPVOID)&lpBuffer, (PUINT)&BufLen))printf("not found\n");else printf("%s\n", lpBuffer);Dest[dwStrFileInfoLen] = '\0';
	strcat(Dest, "FileDescription"); printf("FileDescription: ");
	if (!VerQueryValue(lpData, Dest, (LPVOID)&lpBuffer, (PUINT)&BufLen))printf("not found\n");else printf("%s\n", lpBuffer);Dest[dwStrFileInfoLen] = '\0';
	strcat(Dest, "FileVersion"); printf("FileVersion: ");
	if (!VerQueryValue(lpData, Dest, (LPVOID)&lpBuffer, (PUINT)&BufLen))printf("not found\n");else printf("%s\n", lpBuffer);Dest[dwStrFileInfoLen] = '\0';
	strcat(Dest, "ProductVersion"); printf("ProductVersion: ");
	if (!VerQueryValue(lpData, Dest, (LPVOID)&lpBuffer, (PUINT)&BufLen))printf("not found\n");else printf("%s\n", lpBuffer);Dest[dwStrFileInfoLen] = '\0';
	strcat(Dest, "CompanyName"); printf("CompanyName: ");
	if (!VerQueryValue(lpData, Dest, (LPVOID)&lpBuffer, (PUINT)&BufLen))printf("not found\n");else printf("%s\n", lpBuffer);Dest[dwStrFileInfoLen] = '\0';
	strcat(Dest, "InternalName"); printf("InternalName: ");
	if (!VerQueryValue(lpData, Dest, (LPVOID)&lpBuffer, (PUINT)&BufLen))printf("not found\n");else printf("%s\n", lpBuffer);Dest[dwStrFileInfoLen] = '\0';
	strcat(Dest, "LegalCopyright"); printf("LegalCopyright: ");
	if (!VerQueryValue(lpData, Dest, (LPVOID)&lpBuffer, (PUINT)&BufLen))printf("not found\n");else printf("%s\n", lpBuffer);Dest[dwStrFileInfoLen] = '\0';
	strcat(Dest, "OriginalFileName"); printf("OriginalFileName: ");
	if (!VerQueryValue(lpData, Dest, (LPVOID)&lpBuffer, (PUINT)&BufLen))printf("not found\n");else printf("%s\n", lpBuffer);Dest[dwStrFileInfoLen] = '\0';

	free(lpData);
	return 0;

}

int main()
{

	NTSTATUS status;
	ULONG i;

	PRTL_PROCESS_MODULES ModuleInfo;
	HMODULE hModule = GetModuleHandleA("ntdll.dll");
	NTQUERYSYSTEMINFORMATION fnNtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(hModule, "NtQuerySystemInformation");
	ModuleInfo = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Allocate memory for the module list

	if (!ModuleInfo)
	{
		//printf("\nUnable to allocate memory for module list (%d)\n", GetLastError());
		return -1;
	}

	if (!NT_SUCCESS(status = fnNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, ModuleInfo, 1024 * 1024, NULL))) // 11 = SystemModuleInformation
	{
		//printf("\nError: Unable to query module list (%#x)\n", status);
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		return -1;
	}

	for (i = 0;i < ModuleInfo->NumberOfModules;i++)
	{
		//printf("\n*****************************************************\n");
		//printf("\nImage base: %#x\n", ModuleInfo->Modules[i].ImageBase);
		//printf("\nImage name: %s\n", ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName);
		//printf("\nImage full path: %s\n", ModuleInfo->Modules[i].FullPathName);
		//printf("\nImage size: %d\n", ModuleInfo->Modules[i].ImageSize);
		//printf("\n*****************************************************\n");
		HKEY hkey;
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services", 0, 0x20019, &hkey) == ERROR_SUCCESS)
		{
			for (unsigned int j = 0; ; j++)
			{
				char szSubKey[MAX_PATH] = { 0 };
				DWORD ccName = sizeof(szSubKey);
				FILETIME filetime;
				if (RegEnumKeyExA(hkey, j, szSubKey, &ccName, 0, 0, 0, &filetime) == ERROR_NO_MORE_ITEMS)
					break;

				HKEY hkeyService;
				if (RegOpenKeyExA(hkey, szSubKey, 0, 0x20019, &hkeyService) == ERROR_SUCCESS)
				{
					char szImagePath[MAX_PATH];
					unsigned long datatype = REG_NONE;
					unsigned long dwLen = sizeof(szImagePath);
					memset(szImagePath, 0, sizeof(szImagePath));
					RegQueryValueExA(hkeyService, "ImagePath", NULL, &datatype, szImagePath, &dwLen);
					if (szImagePath[0] && !strcmp(szImagePath, ModuleInfo->Modules[i].FullPathName))
					{
						char szDisplayName[MAX_PATH];
						dwLen = sizeof(szDisplayName);
						memset(szDisplayName, 0, sizeof(szDisplayName));
						RegQueryValueExA(hkeyService, "DisplayName", NULL, &datatype, szDisplayName, &dwLen);

						char szSystemRoot[MAX_PATH];
						if (!strnicmp(szImagePath, "\\systemroot", 11))
						{
							ExpandEnvironmentStringsA("%SystemRoot%", szSystemRoot, MAX_PATH);
							char *p = szSystemRoot; while (*p) p++; p--;
							if (*p != '\\') { *(++p) = '\\'; *++p = '\0'; }
							strcat(p, szImagePath + strlen("\\systemroot\\"));
							szSystemRoot[MAX_PATH - 1] = '\0';
							getversion(szSystemRoot);
						}
						else {
							getversion(szImagePath);
						}

					}
				}
			}
		}
	}

	VirtualFree(ModuleInfo, 0, MEM_RELEASE);
	return 0;


}