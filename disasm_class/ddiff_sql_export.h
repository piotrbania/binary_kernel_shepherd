#ifndef _DDIFFSQL_H
#define _DDIFFSQL_H


#include "danalyze.h"
#include "sql_class.h"


extern class DAnalyze;

class DDiffSqlExport
{
	public:
		DDiffSqlExport();
		~DDiffSqlExport();

		int		check_and_clear_previous(void);
		int		setup(fileinfo_data *FileData1, fileinfo_data *FileData2);
		void	set_diff_source(DDiff	*Diff);

	private:
		int				m1_id;
		int				m2_id;


		DDiff			*Diff;
		DAnalyze		*DA1;
		DAnalyze		*DA2;
		DAnalyze		*DActive;


		ulong32			magic_crc;

#define MAX_SQL_REQUEST_SIZE 1*1000000
		char			request[MAX_SQL_REQUEST_SIZE];
		SQLClass		Sql;
		MYSQL_RES		*res;
		MYSQL_ROW		row;

		fileinfo_data	*FileData1;
		fileinfo_data	*FileData2;
		

		int		delete_module_data(int id);
		int		get_dentry(ulong32 magic_crc);
		int		insert_module(	type_moduleOS moduleOS,
								char *module_name, 
								ulong32 module_imagebase, 
								ulong32 module_filesize,
								char *module_version,
								int number_of_instructions, 
								int number_of_basicblocks,
								double seconds_elapsed_disasm,
								double seconds_elapsed_basicblocks);

		int		insert_dentry(	type_moduleOS moduleOS,
								int patched_module_id,
								int notpatched_module_id,
								double seconds_elapsed_diff);


		int		export_basicblocks(void);
		int		export_basicblocks_do(_dbasicblock *bb_start, BOOL export_matched);
		int		export_this_basicblock(_dbasicblock *bb, DAnalyze *DA, int id, BOOL find_objs=FALSE);
		int		decorate_instr_line(ulong32 instr_rva, char *instr_string, DAnalyze *DA);


		typedef struct obj_match
		{
			ulong32 obj_rva;
			ulong32 obj_matched_rva;
		};

		
	//	typedef hash_map<ulong32 , obj_match*>		type_ObjMatch;

		// ulong32-> obj_rva; obj_matched_rva;
		typedef hash_map<ulong32 , ulong32>			type_ObjMatch;
		type_ObjMatch		MapObjMatch;

		int		get_instr_objs(ulong32 instr_rva, DAnalyze *DA);
		int		export_objs(void);

};

#endif