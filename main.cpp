#include <stdio.h>
#include <conio.h>
#include <windows.h>
#include <assert.h>
#include <stdlib.h>
#include <psapi.h>

#include "danalyze.h"


#define LOG_DIR "J:\\projekty\\binary_shepherding\\logs\\"

char LOG_FILE[255];

void flog(char *text,...)
{
	char buff[512];
	va_list argptr;
	va_start (argptr,text);
	buff[0] = 0;
	vsprintf (buff, text,argptr);
	va_end(argptr);
	FILE *o = fopen(LOG_FILE,"ab");
	assert(o);
	//fwrite(o,buff,1,strlen(buff));
	fwrite(buff,strlen(buff),1,o);
	fclose(o);
}

void flog_plain(char *buff)
{

	FILE *o = fopen(LOG_FILE,"ab");
	assert(o);
	fwrite(buff,strlen(buff),1,o);
	fclose(o);
}

void get_mem_size(void)
{
    PROCESS_MEMORY_COUNTERS pmc;

	if ( GetProcessMemoryInfo( GetCurrentProcess(), &pmc, sizeof(pmc)) )
    {

#define MB_SIZE 1000000
		double r;
#define g_size(x)	{	r = ((double)x / 1024 / 1024); }

		g_size(pmc.PageFaultCount);
		flog( "\tPageFaultCount: %f MB\n", r );

		g_size(pmc.PeakWorkingSetSize);
        flog( "\tPeakWorkingSetSize: %f MB\n", r );

		g_size(pmc.WorkingSetSize);
		flog( "\tWorkingSetSize: %f MB (%d)\n", r, pmc.WorkingSetSize );

		g_size(pmc.QuotaPeakPagedPoolUsage);
        flog( "\tQuotaPeakPagedPoolUsage: %f MB\n", r );
		
		g_size(pmc.QuotaPagedPoolUsage);
        flog( "\tQuotaPagedPoolUsage:  %f MB\n", r );

		g_size(pmc.QuotaPeakNonPagedPoolUsage);
        flog( "\tQuotaPeakNonPagedPoolUsage: %f MB\n", r );


		g_size(pmc.QuotaNonPagedPoolUsage);
        flog( "\tQuotaNonPagedPoolUsage: %f MB\n", r );

		g_size(pmc.PagefileUsage );
        flog( "\tPagefileUsage: %f MB\n", r );

		g_size(pmc.PeakPagefileUsage );
        flog( "\tPeakPagefileUsage: %f MB\n", r );

	}
	else
		flog("%s: GetProcessMemoryInfo failed, error = %08x\n",
		__FUNCTION__, GetLastError());


#undef g_size
}


void get_filesize(char *out_name)
{
	HFILE f = _lopen(out_name, OF_READ);
	if (f == HFILE_ERROR)
	{
		flog("%s: unable to open file (%s)!\r\n", __FUNCTION__, out_name);
		return;
	}

	ulong32 size = GetFileSize((HANDLE)f, NULL);

	double mb = ((double)size / 1024 / 1024);
	flog("NewFileSize = %d bytes (%f MB)\r\n", size, mb);
	_lclose(f);
}

int integrate_all_files(void)
{

#define IN_DIR	"J:\\projekty\\binary_shepherding\\org_files\\win7_real\\"
#define OUT_DIR	"J:\\projekty\\binary_shepherding\\org_files\\win7_real\\integrated\\"

	char out_file[MAX_PATH], file_path[MAX_PATH];
	WIN32_FIND_DATA find_data;
	
	HANDLE hSearch = FindFirstFile(IN_DIR"*.*", &find_data);
	if (hSearch == INVALID_HANDLE_VALUE)
	{
		flog("%s: FindFirstFile failed, error = %d\n", 
			__FUNCTION__, GetLastError());
		return 0;
	}

	do
	{
		if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			continue;

		
		_snprintf(out_file, sizeof(out_file)-1, "%s%s", OUT_DIR, find_data.cFileName);
		DeleteFile(out_file);

		_snprintf(LOG_FILE, sizeof(LOG_FILE)-1, "%s%s.txt", LOG_DIR, find_data.cFileName);
		DeleteFile(LOG_FILE);
		flog("Integrating %s\n", out_file);


		_snprintf(file_path, sizeof(file_path)-1, "%s%s", IN_DIR, find_data.cFileName);

		ulong32 q = find_data.nFileSizeLow / 1000000;
		ulong32 r = find_data.nFileSizeLow % 1000000;
		flog("FileSize = %d,%d MB\n", q, r);



		DAnalyze *DAX = new DAnalyze();
		int rest = DAX->LoadPeFile((char*)file_path);
		if (rest == D_FAILED)
		{
			flog("%s: invalid PE file %s\n", __FUNCTION__, find_data.cFileName);
			DAX->close_symbols();
			delete DAX;
			continue;
		}

		DAX->engine_run();
		//DAX->dump_functions();
		DAX->close_symbols();
		CopyFile(file_path, out_file, FALSE);
		SetFileAttributes(out_file, FILE_ATTRIBUTE_NORMAL);

		DIntegrate *DI = new DIntegrate();
		DI->set_object(DAX);

	
		DI->process_functions();
		DI->dump_integrate_file(out_file);

		get_mem_size();
		delete DI;
		delete DAX;


		get_filesize(out_file);

	} while (FindNextFile(hSearch, &find_data) != 0);


	FindClose(hSearch);
	return 1;
}






int main(void)
{
	FileInfoMgr FileMgr;
	DeleteFile(LOG_FILE);


	_snprintf(LOG_FILE, sizeof(LOG_FILE)-1, "J:\\projekty\\binary_shepherding\\log.txt");
	DeleteFile(LOG_FILE);




//#define FILE_NAMEXA "J:\\projekty\\symbol_test\\lab\\dllz\\03_2011\\freecell.exe"	//usbintel.sys"

//#define FILE_NAMEXA "J:\\projekty\\msg_test3\\Release\\msgtest.exe"

#define FILE_NAMEXA "J:\\projekty\\binary_shepherding\\win32kORG.sys"	//ntkrnlpaNEW.exe"	//srv2VISTA.sys"
//#define FILE_NAMEXA "J:\\projekty\\msg_test2\\Release\\msg_test2.exe"

//#define FILE_NAMEXA "J:\\asm\\2.exe"
#define OUT_FILE	"J:\\projekty\\binary_shepherding\\win32k.sys"	//ntkrnlpa.exe"

	DAnalyze *DAX = new DAnalyze();
	DAX->LoadPeFile((char*)FILE_NAMEXA);
	DAX->engine_run();
	DAX->dump_functions();
	DAX->close_symbols();

	DeleteFile(OUT_FILE);
	CopyFile(FILE_NAMEXA, OUT_FILE, FALSE);
	SetFileAttributes(OUT_FILE, FILE_ATTRIBUTE_NORMAL);

	DIntegrate *DI = new DIntegrate();
	DI->set_object(DAX);

	//DAX->debug_compare_ida_data();
	DI->process_functions();
	
	DI->dump_integrate_file(OUT_FILE);

	get_mem_size();
	DI->compare_IDA_data();

	delete DI;
	delete DAX;

	return 0;
}