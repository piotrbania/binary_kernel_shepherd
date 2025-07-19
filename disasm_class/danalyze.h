#ifndef _DANALYZE_H
#define _DANALYZE_H


#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <windows.h>
#include <math.h>
#include <list>
#include <map>
#include <vector>
#include <hash_map>


#include "danalyze_options.h"

#if DA_USE_SQL == 1
#include "sql_class.h"
#endif

#ifdef _BINSHEP
#include "dintegrate.h"
#endif

/*
#if DA_DEBUG_MEM == 1
#define _CRTDBG_MAPALLOC
#define CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#define DBG_NEW new ( _NORMAL_BLOCK , __FILE__ , __LINE__ )
#define new DBG_NEW

#endif
*/


using namespace std;
using namespace stdext;


#include "disasm.h"
#include "disit_i_table.h"
#include "disit_func.h"
#include "disit_types.h"
#include "dfuncs.h"
#include "symbol_class.h"
#include "dchecksum.h"
#include "dbasicblock.h"
#include "dfunction.h"
#include "ddiff.h"
#include "dreferences.h"


#include "timer.h"
#include "libdasm.h"

#include "fileinfo.h"

#define	TIME_TEST			1


#ifdef _WIN64
#define debug_break DebugBreak()
#define bp(var,x)				{ if ((ulong32)var == (ulong32)x) debug_break; }
#else
#define debug_break _asm { int 3 };
#define bp(var,x)				{ if ((ulong32)var == (ulong32)x) debug_break; }
#endif


#define align(x,y)				(((x)+(y)-1)&(~((y)-1)))
#define SAFE_DELETE(x)				{ if (x) delete []x; }
#define SAFE_DELETE_C(x)			{ if (x) delete x; }

#define	D_OK		1
#define D_FAILED	0
#define PAGE_SIZE	4096
#define D_NOMEM		-1

#define MAX_ASCII_CHARS			10
#define MAX_UNICODE_CHARS		10


#define	JMP_OPCODE				0xE9

#define MAX_HEURISTISC_INSTR	10

extern void flog(char *text,...);
void flog_plain(char *buff);


typedef vector<ulong32>		type_FutureAddrList;
typedef vector<_dinstr*>	type_InstrList;				// perhaps change the type to vector (later)


enum	type_addr
{
	TADDR_INVALID	=	0,		// addr is invalid
	TADDR_ANALYZED,				// addr was analyzed already
	TADDR_GOOD					// addr is correct		
};



#define DSTATUS_GETNEW	0	// disassembly ok, now take new future addr
#define DSTATUS_INVALID	-1	// invalid addr or disassembler error


#define D_CRC_FLAG_IMM			0x000100		//  imm data found
#define D_CRC_FLAG_IMM_REL		0x000800		//  imm data is relocable
#define D_CRC_FLAG_MEMIMM		0x001000		//  mem imm32 data found
#define D_CRC_FLAG_MEMIMM_REL	0x008000		//	mem imm32 rel
#define D_CRC_FLAG_MEMSRC		0x002000		//  mem acts as source
#define D_CRC_FLAG_MEMDEST		0x004000		//  mem acts as dest
#define D_CRC_FLAG_JCC			0x010000		//  jcc found
#define D_CRC_FLAG_JMP			0x100000		//  jmp found


class DAnalyze
{

	public:
		DAnalyze();
		~DAnalyze();

		void	debug_compare_ida_data(void);

		int			LoadPeFile(char *name);
		int			LoadPeFile64(char *name);

		int			engine_run(void);

		void		close_symbols(void) { Symbols->clean_up(); } 

		// diff object
		friend class DDiff;
		DDiff		*Diff;

#if DA_USE_SQL == 1
		int get_instruction_text(ulong32 rva_addr, char *instr_string);
		friend class DDiffSqlExport;
#endif


		// basic block functions
		type_BBList			BasicBlockList;
		type_BBMap			BasicBlockMap;


		void				dump_functions(void);

#ifdef _BINSHEP
		friend class DIntegrate;
#endif

	private:

		ulong32							o_filesize;				// debug only
		char							o_filename[MAX_PATH];	// debug only


		ulong32							m_imagebase;		// current imagebase
		ulong32							o_imagebase;		// original imagebase
		ulong32							o_imagesize;		// original imagesize
		ulong32							sec_align;			// section alignment


		// keep a copy for 64 bit stuff also
		PIMAGE_DOS_HEADER				pMZ;
		PIMAGE_NT_HEADERS				pPE;
		PIMAGE_SECTION_HEADER			pSH;
		PIMAGE_IMPORT_DESCRIPTOR		pIMP;
		PIMAGE_EXPORT_DIRECTORY			pEXP;

		// 64bit stuff ----------------------------------------------
		ulong64							m_imagebase64;
		ulong64							o_imagebase64;
		PIMAGE_NT_HEADERS64				pPE64;


		int flag_relocs64(void);
		int flag_imports64(void);

		inline ulong64 lrva2va64(ulong32 rva)				{ return (ulong64)(rva + this->m_imagebase); } 
		inline ulong32 lva2rva64(ulong64 va)				{ return (ulong32)(va - this->m_imagebase); } 
		inline ulong64 orva2va64(ulong32 rva)				{ return (ulong64)(rva + this->o_imagebase); } 
		inline ulong32 ova2rva64(ulong64 va)				{ return (ulong32)(va - this->o_imagebase); } 

		// ----------------------------------------------------------




		type_FutureAddrList				ProspectAddrList;
		type_FutureAddrList				FutureAddrList;
		type_InstrList					InstrList;

		_bin_data						BinData;


		BOOL					ready;		// ready for analysis?

		// private functions
		
		int			flag_relocs(void);
		int			flag_imports(void);

		int			add_functions_ep(void);			// add functions to FutureAddrList
		int			add_functions_exports(void);	// add exported functions to FutureAddrList
		int			add_functions_symbols(void);	// add symbol functions to FutureAddrList
		int			add_functions_relocs(void);		// add functions found by relocs to FutureAddrList
		int			add_functions_heuristics(void); // add functions to FutureAddrList found by heuristisc stuf
		

		BOOL		is_deadend_import_api(char	*api_name);
		ulong32		get_next_executable_rva(type_flags *flags, ulong32 current_rva);
		
		void		check_operands_and_set_flags(_dinstr *di, _dis_data *dd);
		void		check_for_vtable(_dinstr *di, _dis_data *dd);
		BOOL		add_vtable_entries(ulong32 mem_rva, BOOL strict_mode=FALSE);
		inline void		check_semantic_nops(_dinstr *di, _dis_data *dd);


		ulong32			process_instruction(ulong32 rva, _dinstr **di_out);		
		type_addr	is_prospect_rva_good(ulong32 rva, _dinstr *di);
		int				engine_process_prospects(void);


		void		set_future_addr_function(ulong32 rva_addr,  bool validate=false);
		void		set_future_addr(ulong32 rva_addr);
		void		set_future_addr_prospect(ulong32 rva_addr);

		ulong32		get_future_addr(void);			// get last future addr from the list
		type_addr	is_future_addr_correct(ulong32 rva, bool remove=false);

		BOOL		is_prologue(ulong32 rva, BOOL strict_mode=TRUE);		// is prologue signature found?
		BOOL		can_be_code_strict(ulong32 rva);
		BOOL		can_be_code_weak(ulong32 rva);
		BOOL		can_be_code_using_disasm(ulong32 rva);
		int			can_be_ascii(uchar *p);	//return the len of ascii characters at 
		int			can_be_unicode(uchar *p);	//return the len of unicode characters at p


		int			remove_bad_area(type_InstrList	*InstrBlock);
		inline		BOOL	is_mem_operand_in_range(ulong32 rva, _dis_data *dd);


		_dinstr*	new_dinstr(ulong32 rva_addr, uchar *data_ptr, int8 len, int emul_int);
		inline _dinstr*	get_dinstr_from_rva(ulong32 rva_addr) { return this->BinData.fast_instrs[rva_addr]; }

		int			debug_find_future_addr(ulong32 rva_addr);
		int			debug_show_instruction(ulong32 rva_addr);
		void		debug_show_flags_for_rva(ulong32 rva_addr);
		void		debug_dump_basicblocks(void);
		int			debug_show_instruction_from_data(uchar *data);

		// inline functions
		inline ulong32 lrva2va(ulong32 rva)				{ return (ulong32)((ulong32)rva + (ulong32)this->m_imagebase); } 
		inline ulong32 lva2rva(ulong32 va)				{ return (ulong32)((ulong32)va - (ulong32)this->m_imagebase); } 
		inline ulong32 orva2va(ulong32 rva)				{ return (ulong32)((ulong32)rva + (ulong32)this->o_imagebase); } 
		inline ulong32 ova2rva(ulong32 va)				{ return (ulong32)((ulong32)va - (ulong32)this->o_imagebase); } 

		ulong32 orva2raw(ulong32 rva);


		inline BOOL	   is_addr_in_range(ulong32 rva)	{ if ((rva >= 0) && (rva < this->BinData.data_size)) { return TRUE; } else { return FALSE; } }


		void	debug_compare_ida();

		// symbols
		SymbolClass *Symbols;
		// checksum
		DChecksum	*Checksum;




	

		int					bb_not_resolved;
		_dbasicblock		*find_basicblock(ulong32 rva_addr);
		_dbasicblock		*new_basicblock(ulong32 start_rva);
		int					make_basicblocks(void);
		int					fill_and_close_basicblock(_dbasicblock *bb);
		int					fill_basicblock_lists(_dbasicblock *bb, _dinstr *di, type_flags iflags);
		int					write_vtable_to_basicblock_list(ulong32 vtable_rva, type_BBChildFunctions *list);
		int					set_bytes_for_checksum(_dbasicblock *bb, _dinstr *di, type_flags iflags);
		int					resolve_basicblock_informations(void);
		void				resolve_basicblock_list(type_BBChildFunctions *list);
		void				add_parents_to_basicblock(_dbasicblock *bb);
		BOOL				try_to_merge_basicblocks(void);
		BOOL				merge_with_parent(_dbasicblock *bb);	// recursive
		BOOL				merge_with_parent_jmp(_dbasicblock *bb, _dbasicblock *bb_child);

	

		// functions for Functions :-)
		type_FunctionList	FunctionList;
		type_FunctionMap	FunctionMap;
		int					make_functions(void);		// makes functions from basicblocks
		_dfunction			*new_function(_dbasicblock *bb_start);
		_dfunction			*find_function_by_rva(ulong32 rva);
		int					walk_function_basicblocks(_dfunction *df);
		BOOL				was_bb_analyzed(_dbasicblock *bb, type_BBMap *AnalyzedBBList);
		int					get_functions_for_basicblock(_dbasicblock *bb, type_FunctionList *OutFuncList);
		void				get_functions_for_basicblock_recursive(_dbasicblock		*bb, 
											type_FunctionList	*OutFuncList,
											type_BBMap			*BBVisitedMap);


		// references (xrefs)
		type_ReferenceMap	ReferenceMap;
		_reference_entry	*reference_add(ulong32 obj_rva, _dbasicblock *bb, _dinstr *instr);
		


		
		
		// for sql export and stats
#ifdef TIME_TEST == 1

		Timer		Czasomierz;
		double		seconds_elapsed_disassembly;
		double		seconds_elapsed_basicblocks;

#endif


};



#endif