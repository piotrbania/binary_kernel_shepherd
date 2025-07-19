#ifndef _DINTEGRATE_H
#define _DINTEGRATE_H


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
#include "dfunction.h"
#include "danalyze_options.h"
#include "dintegrate_structs.h"


#include "timer.h"

extern void flog(char *text,...);


#define DI_DEBUG_IT			0

#define DI_ANTIROP			0			// debug testing antirop


#define D_OK				1
#define D_FAILED			0


#define FUNC_ALIGN			16
#define PATCH_SIZE			5

#define DI_INSTRUMENT				1
#define DI_INSTRUMENT_RET			1
#define DI_INSTRUMENT_JMPI			1
#define DI_INSTRUMENT_CALLI			1
#define DI_INSTRUMENT_CALLREL		0			// not needed for now


#define DI_USE_PAX					0			// use pax instrumentation

#define DI_HOOK_ALL					1
#define SKIP_INIT_SECTION			0			// dont hook init section




// dont use those
#define HARDCORE_FUNC_PATCHING		0
#define DEBUG_INSTRUMENTATION		0		// add DbgPrint to f. prolog

#define DEBUG_FIX					0		// just for bug-hunting

#define DBG_PRINT_RVA				0x00050E92


//#define EXTRA_OPERAND_CHECK			1		<- in preprocessor



extern DWORD get_pe_checksum(char *file_name);

	// debug only: antirop 02.11.2011
		typedef map<ulong32, _dbasicblock*>	type_SharedBB;
		// end debug


class DIntegrate
{
	public:
		DIntegrate();
		~DIntegrate();
		void	set_object(class DAnalyze *DA);

		int		process_functions(void);

		void	dump_integrate_file(char *file);
		void	compare_IDA_data(void);

private:
		class	DAnalyze *DA;

		void	terminate(void);

		void	dump_function(_dfunction *func);

		void	DFS_clear(_dfunction *func);
		int		DFS_start(_dfunction *func, _dbasicblock *bb_start);
		inline	_bb_iext*		new_bb_iext(void);
		inline	_instr_iext*		new_instr_iext(_dinstr	*di_org, uchar *data_ptr, uint8 data_size); 
		inline  BOOL	was_iext_data_allocated(_instr_iext *iext);

		ulong32 DFSInTime;
		int		DFS_go(_dfunction *func, _dbasicblock *bb);
		int		fill_instructions(_dbasicblock *bb);


		int		calculate_new_bb_size(void);
		int		integrate_stage1(void);
		int		integrate_stage2(void);
		ulong32	integrate_stage1_func(_dfunction *func, ulong32 start_rva);

		int		integrate_stage2_func(_dfunction *func);
		int		instrument_instr(_instr_iext *iext, _bb_iext *bbi, BOOL usePAX);
		int		instrument(void);
		int		debug_instrument_function(_dfunction *func);


		inline	BOOL link_JMP(_instr_iext *iext, _bb_iext *bbi);
		inline	void instrument_CALLI(_instr_iext *iext);
		inline	void instrument_JMPI(_instr_iext *iext);
		inline	void instrument_RET(_instr_iext *iext, BOOL usePAX);
		inline	void instrument_CALLREL(_instr_iext *iext);
		inline	void extend_JCC(_instr_iext *iext);
		inline	void extend_JMP(_instr_iext *iext);
		inline	void extend_JECXZ(_instr_iext *iext);
		inline  void fix_nextlink(_instr_iext *iext, _bb_iext *bbi);
		inline	void repair_interrupted_block(_bb_iext		*bbi, _instr_iext *iext);


		inline	void copy_original_instruction(_instr_iext *iext);

		inline	uchar* new_iext_data(_instr_iext *iext, int size);


		int		write_relocation_entry_for_instrumented_CALLi(_bb_iext		*bbi, _instr_iext *iext, ulong32 i_new_rva);
		int		write_relocation_entry_for_interrupted_bb(_bb_iext		*bbi, _instr_iext *iext, ulong32 i_new_rva);
		int		write_relocation_entry(_bb_iext		*bbi,  _instr_iext *iext, ulong32 i_new_rva);
		int		write_callback_entry(_bb_iext *bbi, _instr_iext *iext, ulong32 i_new_rva);


		void	dump_instrumentation(_instr_iext *iext);

		ulong32	magic_key;


		type_RelocsList			RelocsList;			// relocations (each ulong32 represents rva entry)
		type_CallbacksList		CallbacksList;
		type_BBIExtCallRelList  CallRelList;			// list of basicblocks ended by CALL REL
		

		ulong32		init_section_rva_start;
		ulong32		init_section_rva_end;
		void		find_INIT_section(void);
		inline BOOL	is_rva_in_INIT_section(ulong32 rva);


		BOOL		is_hardcore_hook_suitable(ulong32 func_rva);
		int			hook_calls(uchar *file_data, ulong32 new_code_baseRVA);
		int			hook_functions(uchar *file_data, ulong32 new_code_baseRVA);
		ulong32		get_org_relocs_size(ulong32 reloc_section_rva);
		ulong32		compute_checksum(char *file_name);

		uchar		*generate_relocs(ulong32 new_relocRVA);
		uchar		*computed_relocs;
		ulong32		computed_relocs_align_size;
		ulong32		computed_relocs_size;

		BOOL		is_bad_reloc_addr(ulong32 reloc_rva);
		uchar		*generate_org_relocs(ulong32 reloc_section_rva);
		uchar		*computed_org_relocs;
		ulong32		computed_org_relocs_size;


		BOOL		is_ascii_char(uchar p);
		BOOL		is_bb_asciiunicode(_dbasicblock *bb);
		BOOL		is_func_hookable(_dfunction *func);
		BOOL		determine_hook_ability(_dfunction *func);


		int			debug_repair_count;
		BOOL		restore_call(_dfunction *func, _bb_iext *bbi, _instr_iext *iext, ulong32 iRVA);
		int			debug_fix_func(_dfunction *func, _bb_iext *bbi, _instr_iext *iext, ulong32 iRVA);
		ulong32		total_align_size;			// total pad bytes


		// this is for ntoskrnl / ntkrnlpa only
		ulong32		rva_KiInterruptTemplate;
		ulong32		rva_KiUnlockDispatcherDatabase;
		BOOL		is_ntkrnlpa;

		BOOL			resolve_KeFlushCurrentTb_issue(ulong32 rva_KeFlushCurrentTb);
		inline BOOL		is_forbidden_function(_dfunction *func);
		int				setup_invalid_addrs(void);
		type_BlackList	BlackListLoc;


		// debug only: antirop 02.11.2011
		typedef map<ulong32, _dbasicblock*>	type_SharedBB;
		type_SharedBB	SharedBBList;
		type_SharedBB	VisitedBBList;
		int			MarkSharedBasicBlocks(void);
		int			EraseFunction(uchar *file_data, _dfunction *func);
		ulong32		IsSharedBasicBlock(ulong32 rva_addr);
		ulong32		IsVisitedBasicBlock(ulong32 rva_addr);
		// end debug only


		// for callback emitting
		ulong32		rva_callback_RET;
		ulong32		rva_callback_JMPI;
		ulong32		rva_callback_CALLI;
		int			generate_callbacks(void);
		uchar		*callback_mem;
		int			callback_mem_size;


		// time testing
		Timer		Czasomierz;

};

#endif