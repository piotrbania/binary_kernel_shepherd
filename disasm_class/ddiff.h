#ifndef _DDIFF_H
#define _DDIFF_H


#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <windows.h>
#include <math.h>
#include <list>
#include <map>
#include <vector>
#include <hash_map>
#include <algorithm>


#include "disit_types.h"
#include "dchecksum.h"
#include "dbasicblock.h"
#include "symbol_class.h"
#include "danalyze_options.h"

#include "fileinfo.h"	// sql support



#if DA_USE_SQL == 1
#include "ddiff_sql_export.h"
#endif



using namespace std;
using namespace stdext;




#if DDIFF_SHOW_OUTPUT == 1
	struct debug_obj_match
	{
		ulong32 obj;
		ulong32 obj_match;	
	};
#endif

// multiple hash map for fingerpring matching


typedef hash_multimap<ulong64, struct __dbasicblock*>		type_AdlerFingerPrintMap;		// entire checksum adler
typedef hash_multimap<ulong64, struct __dbasicblock*>		type_PrimaryFingerPrintMap;		// entire checksum
typedef hash_multimap<ulong32, struct __dbasicblock*>		type_SecondaryFingerPrintMap;	// cfg part
typedef hash_multimap<ulong32, struct __dbasicblock*>		type_ByteFingerPrintMap;		// just adler bytes
typedef hash_multimap<ulong32, struct __dbasicblock*>		type_WeakFingerPrintMap;		// imm oprands ignored etc.



typedef pair<type_AdlerFingerPrintMap::iterator,type_AdlerFingerPrintMap::iterator> type_AdlerPrintPair;
typedef pair<type_PrimaryFingerPrintMap::iterator,type_PrimaryFingerPrintMap::iterator> type_FingerPrintPair;
typedef pair<type_SecondaryFingerPrintMap::iterator,type_SecondaryFingerPrintMap::iterator> type_SecFingerPrintPair;
typedef pair<type_ByteFingerPrintMap::iterator,type_ByteFingerPrintMap::iterator> type_ByteFingerPrintPair;
typedef pair<type_WeakFingerPrintMap::iterator,type_WeakFingerPrintMap::iterator> type_WeakFingerPrintPair;


typedef struct __dbbestmatches
{
	_dbasicblock		*match;
	int					match_level;	// max match_level = dbmatch->bb->ChildList.size()+ParentsList.size()

} _dbbestmatches;

typedef vector<_dbbestmatches*>	type_BBBestMatchesList;

typedef struct __dbbmatch
{
	_dbasicblock			*bb;

	// matches for basicblock sorted by the match_level
	type_BBBestMatchesList	BestMatches;

} _dbbmatch;


typedef vector<_dbbmatch*>			type_BBHMList;




class DDiff
{
	public:
		DDiff();
		~DDiff();
		void set_src_dest_objects(class DAnalyze *A1, class DAnalyze *A2);


		int		make_basicblock_fingerprint(_dbasicblock *bb);
		int		compare_basicblocks(void);

		type_PrimaryFingerPrintMap		PrimaryFingerPrintMap;
		type_SecondaryFingerPrintMap	SecondaryFingerPrintMap;
		type_AdlerFingerPrintMap		AdlerFingerPrintMap;
		type_ByteFingerPrintMap			BytesFingerPrintMap;
		type_WeakFingerPrintMap			WeakFingerPrintMap;

		// for sql export

#if DA_USE_SQL == 1
		int				diff_and_export2sql(fileinfo_data *FileData1, fileinfo_data *FileData2);

		friend class DDiffSqlExport;
		DDiffSqlExport	*DiffSql;
		
#endif


	private:
		class DAnalyze		*Analyze1;
		class DAnalyze		*Analyze2;

		type_BBList						*BBList1;
		type_BBList						*BBList2;

		type_PrimaryFingerPrintMap		*PMap1;
		type_PrimaryFingerPrintMap		*PMap2;
		type_SecondaryFingerPrintMap	*SMap1;
		type_SecondaryFingerPrintMap	*SMap2;
		type_AdlerFingerPrintMap		*AMap1;
		type_AdlerFingerPrintMap		*AMap2;

		type_ByteFingerPrintMap			*BMap1;
		type_ByteFingerPrintMap			*BMap2;
		type_WeakFingerPrintMap			*WMap1;
		type_WeakFingerPrintMap			*WMap2;


		type_FunctionMap				UmatchedFunctionsMap;
		type_FunctionList				UnmatchedFunctions;




		int					match_process_pair(_dbasicblock	*bb1, int count, type_AdlerPrintPair *pair, BOOL report_unmatched);

		int					match_unmatched_basicblock(void);

		void				debug_list_function_basicblocks(_dfunction *df);

		_dbbestmatches		*match_by_level(_dbasicblock *bb, _dbasicblock *bb_similar);
		int					calc_match_level(type_BBList *list_b1, type_BBList *list_b2);
		int					hardcore_matching(type_BBList *list_b1, type_BBList *list_b2, _dbbmatch *dbm);
		BOOL				match_by_name(_dbasicblock *bb);
		BOOL				match_by_name_do(_dbasicblock *bb);
		BOOL				compare_cfg(_dbasicblock *bb1, _dbasicblock *bb2, BOOL parents);
		BOOL				match_by_bytes(_dbasicblock *bb1);
		BOOL				match_by_weak_bytes(_dbasicblock *bb1);


		ulong32				match_object(ulong32 obj_rva);

		ulong32				match_object_by_symbol(ulong32 obj_rva);

		ulong32				match_object_by_heuristisc_get_rva(ulong32 obj_rva, ulong32 symbol_rva, ulong32 *symbol_rva_out);
		ulong32				match_object_by_heuristisc(ulong32 obj_rva);
		ulong32				match_object_by_references(ulong32 obj_rva);
		void				debug_find_obj_instrs_in_bb(_dbasicblock *bb);



		int					pick_best_match(_dbbmatch *dbm);
	


	
		type_BBHMList		NotMatchedBasicBlocks;
				


		// for export and stats
		int		debug_single_num;
		int		debug_multiple_num;
		int		debug_none_num;
		int		debug_matched_objects;		// only for changed code parts
		int		debug_not_matched_objects;

		double		seconds_elapsed_diff;


};


#endif