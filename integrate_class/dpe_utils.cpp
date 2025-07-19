#include <windows.h>
#include <imagehlp.h>


DWORD get_pe_checksum(char *file_name)
{
	DWORD		old_checksum = 0, checksum = 0;

	if (MapFileAndCheckSum(file_name,(PDWORD)&old_checksum, (PDWORD)&checksum) != CHECKSUM_SUCCESS)
		return NULL;

	return checksum;

}




