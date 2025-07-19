#ifndef _DFUNCS_H
#define _DFUNCS_H

#include "disit_types.h"


typedef ulong32	type_flags;					// maybe we will be able to shrink it later 

/*
* following flags and functions apply only to the flags for binary data 
* not single instrs
*/

#define DA_FLAG_NOT_USED						0x00000000
#define	DA_FLAG_INSTR							0x00000001		// zwyczajna instrukcja
#define DA_FLAG_EXECUTABLE_AREA					0x00000002		// region is executable (data is not executable)
#define DA_FLAG_ANALYZED						0x00000004
#define DA_FLAG_HEAD							0x00000008
#define DA_FLAG_TAIL							0x00000010
#define DA_FLAG_LABEL							0x00000020
#define DA_FLAG_DATA							0x00000040
#define DA_FLAG_RELOC_DATA						0x00000080
#define DA_FLAG_IMPORT_DATA						0x00000100
#define DA_FLAG_BB_END							0x00000200		// instruction ends basicblock
#define DA_FLAG_FUNCTION_START					0x00000400		// start of a function
#define DA_FLAG_INSTR_SYMBOL_IN_MEMIMM			0x00000800		// symbol addr in memory imm operand
#define DA_FLAG_INSTR_SYMBOL_IN_IMM				0x00001000		// symbol addr in imm operand
#define DA_FLAG_INSTR_USES_VTABLE				0x00002000		// vtable located for jmp/call [reg*4+vtable]
#define DA_FLAG_INSTR_USES_IMPORTED_API			0x00004000		// call [mem]/jmp [mem] -> where mem is in IAT
#define DA_FLAG_INSTR_RELOCABLE_DATA_IN_MEMIMM	0x00008000		// relocable data in memimm
#define DA_FLAG_INSTR_RELOCABLE_DATA_IN_IMM		0x00010000		// relocable data in imm
#define DA_FLAG_INSTR_CALL						0x00020000		// instruction is a CALL (REL/ABS)
#define DA_FLAG_INSTR_JMP						0x00040000		// instruction is a JMP (REL/ABS)									
#define DA_FLAG_INSTR_JCC						0x00080000		// instruction is a JCC/LOOP etc.
#define DA_FLAG_INSTR_SEMANTIC_NOP				0x00100000		// instruction is a semantic nop
#define DA_FLAG_INSTR_RETURN					0x00200000		// instruction is a return
#define DA_FLAG_IMPORT_DATA_DEADEND				0x00400000		// deadend api (like ExitProcess etc)
#define DA_FLAG_FUNC_DEADEND					0x00800000		// function never returns (like KeBugCheckEx in ntoskrnl)
#define DA_FLAG_RELOC_XREF						0x01000000		// location was referenced by relocs
#define DA_FLAG_HAS_SYMBOL						0x02000000		// location has symbols?
#define DA_FLAG_FUNC_EXPORTED					0x04000000		// exported function
#define DA_FLAG_DONT_MERGE						0x08000000		// dont merge this block
#define DA_FLAG_ACCESSED_AS_DATA				0x10000000		// location was accessed as [mem]
#define DA_FLAG_BB_INTERRUPTED					0x20000000		// basicblock was interrupted by int 3 or sth (dodano 30.03.2011)
#define DA_FLAG_PROSPECT						0x40000000		// instruction was a prospect



inline void daSET_F_INSTR(type_flags *f)								{	*f |= 	DA_FLAG_INSTR;	}
inline void daSET_F_EXECUTABLE_AREA(type_flags *f)						{	*f |= 	DA_FLAG_EXECUTABLE_AREA;	}
inline void daSET_F_ANALYZED(type_flags *f)								{	*f |= 	DA_FLAG_ANALYZED;	}
inline void daSET_F_HEAD(type_flags *f)									{	*f |= 	DA_FLAG_HEAD;	}
inline void daSET_F_TAIL(type_flags *f)									{	*f |= 	DA_FLAG_TAIL;	}
inline void daSET_F_LABEL(type_flags *f)								{	*f |= 	DA_FLAG_LABEL;	}
inline void daSET_F_DATA(type_flags *f)									{	*f |= 	(*f & ~DA_FLAG_INSTR) | DA_FLAG_DATA;	}
inline void daSET_F_RELOC_DATA(type_flags *f)							{	*f |= 	DA_FLAG_RELOC_DATA;	}
inline void daSET_F_IMPORT_DATA(type_flags *f)							{	*f |= 	DA_FLAG_IMPORT_DATA; }
inline void daSET_F_BB_END(type_flags *f)								{	*f |= 	DA_FLAG_BB_END; }
inline void daSET_F_FUNCTION_START(type_flags *f)						{	*f |= 	DA_FLAG_FUNCTION_START; }
inline void daSET_F_INSTR_SYMBOL_IN_MEMIMM(type_flags *f)				{	*f |= 	DA_FLAG_INSTR_SYMBOL_IN_MEMIMM; }
inline void daSET_F_INSTR_SYMBOL_IN_IMM(type_flags *f)					{	*f |= 	DA_FLAG_INSTR_SYMBOL_IN_IMM; }
inline void daSET_F_INSTR_USES_VTABLE(type_flags *f)					{	*f |= 	DA_FLAG_INSTR_USES_VTABLE; }	
inline void daSET_F_INSTR_USES_IMPORTED_API(type_flags *f)				{	*f |= 	DA_FLAG_INSTR_USES_IMPORTED_API; }
inline void daSET_F_INSTR_RELOCABLE_DATA_IN_MEMIMM(type_flags *f)		{	*f |= 	DA_FLAG_INSTR_RELOCABLE_DATA_IN_MEMIMM; }
inline void daSET_F_INSTR_RELOCABLE_DATA_IN_IMM(type_flags *f)			{	*f |= 	DA_FLAG_INSTR_RELOCABLE_DATA_IN_IMM; }
inline void daSET_F_INSTR_CALL(type_flags *f)							{	*f |= 	DA_FLAG_INSTR_CALL; }	
inline void daSET_F_INSTR_JMP(type_flags *f)							{	*f |= 	DA_FLAG_INSTR_JMP; }	
inline void daSET_F_INSTR_JCC(type_flags *f)							{	*f |= 	DA_FLAG_INSTR_JCC; }	
inline void daSET_F_INSTR_SEMANTIC_NOP(type_flags *f)					{	*f |= 	DA_FLAG_INSTR_SEMANTIC_NOP; }
inline void daSET_F_INSTR_RETURN(type_flags *f)							{	*f |= 	DA_FLAG_INSTR_RETURN; }
inline void daSET_F_IMPORT_DATA_DEADEND(type_flags *f)					{	*f |= 	DA_FLAG_IMPORT_DATA_DEADEND; }
inline void daSET_F_FUNC_DEADEND(type_flags *f)							{	*f |= 	DA_FLAG_FUNC_DEADEND; }
inline void daSET_F_RELOC_XREF(type_flags *f)							{	*f |= 	DA_FLAG_RELOC_XREF; }
inline void daSET_F_HAS_SYMBOL(type_flags *f)							{	*f |= 	DA_FLAG_HAS_SYMBOL; }
inline void daSET_F_FUNC_EXPORTED(type_flags *f)						{	*f |= 	DA_FLAG_FUNC_EXPORTED; }
inline void daSET_F_DONT_MERGE(type_flags *f)							{	*f |= 	DA_FLAG_DONT_MERGE; }



inline BOOL daIS_F_INSTR(type_flags f)								{	return (f & DA_FLAG_INSTR);	}
inline BOOL daIS_F_EXECUTABLE_AREA(type_flags f)						{	return (f & DA_FLAG_EXECUTABLE_AREA);	}
inline BOOL daIS_F_ANALYZED(type_flags f)								{	return (f & DA_FLAG_ANALYZED);	}
inline BOOL daIS_F_HEAD(type_flags f)									{	return (f & DA_FLAG_HEAD);	}
inline BOOL daIS_F_TAIL(type_flags f)									{	return (f & DA_FLAG_TAIL);	}
inline BOOL daIS_F_LABEL(type_flags f)									{	return (f & DA_FLAG_LABEL);	}
inline BOOL daIS_F_DATA(type_flags f)									{	return (f & DA_FLAG_DATA);	}
inline BOOL daIS_F_RELOC_DATA(type_flags f)								{	return (f & DA_FLAG_RELOC_DATA);	}
inline BOOL daIS_F_IMPORT_DATA(type_flags f)							{	return (f & DA_FLAG_IMPORT_DATA);	}
inline BOOL daIS_F_BB_END(type_flags f)									{	return (f & DA_FLAG_BB_END);	}
inline BOOL daIS_F_FUNCTION_START(type_flags f)							{	return (f & DA_FLAG_FUNCTION_START);	}
inline BOOL daIS_F_INSTR_SYMBOL_IN_MEMIMM(type_flags f)					{	return (f & DA_FLAG_INSTR_SYMBOL_IN_MEMIMM); }
inline BOOL daIS_F_INSTR_SYMBOL_IN_IMM(type_flags f)					{	return (f & DA_FLAG_INSTR_SYMBOL_IN_IMM); }
inline BOOL daIS_F_INSTR_USES_VTABLE(type_flags f)						{	return (f & DA_FLAG_INSTR_USES_VTABLE); }	
inline BOOL daIS_F_INSTR_USES_IMPORTED_API(type_flags f)				{	return (f & DA_FLAG_INSTR_USES_IMPORTED_API); }
inline BOOL daIS_F_INSTR_RELOCABLE_DATA_IN_MEMIMM(type_flags f)			{	return (f & DA_FLAG_INSTR_RELOCABLE_DATA_IN_MEMIMM); }
inline BOOL daIS_F_INSTR_RELOCABLE_DATA_IN_IMM(type_flags f)			{	return (f & DA_FLAG_INSTR_RELOCABLE_DATA_IN_IMM); }
inline BOOL daIS_F_INSTR_CALL(type_flags f)								{	return (f & DA_FLAG_INSTR_CALL); }	
inline BOOL daIS_F_INSTR_JMP(type_flags f)								{	return (f & DA_FLAG_INSTR_JMP); }	
inline BOOL daIS_F_INSTR_JCC(type_flags f)								{	return (f & DA_FLAG_INSTR_JCC); }	
inline BOOL daIS_F_INSTR_SEMANTIC_NOP(type_flags f)						{	return (f & DA_FLAG_INSTR_SEMANTIC_NOP); }	
inline BOOL daIS_F_INSTR_RETURN(type_flags f)							{	return (f & DA_FLAG_INSTR_RETURN); }	
inline BOOL daIS_F_IMPORT_DATA_DEADEND(type_flags f)					{	return (f & DA_FLAG_IMPORT_DATA_DEADEND);	}
inline BOOL daIS_F_FUNC_DEADEND(type_flags f)							{	return (f & DA_FLAG_FUNC_DEADEND);	}
inline BOOL daIS_F_RELOC_XREF(type_flags f)								{	return (f & DA_FLAG_RELOC_XREF	);	}
inline BOOL daIS_F_HAS_SYMBOL(type_flags f)								{	return (f & DA_FLAG_HAS_SYMBOL);	}
inline BOOL daIS_F_FUNC_EXPORTED(type_flags f)							{	return (f & DA_FLAG_FUNC_EXPORTED);	}
inline BOOL daIS_F_DONT_MERGE(type_flags f)								{	return (f & DA_FLAG_DONT_MERGE);	}


inline BOOL	daIS_USING_SYMBOLS(type_flags f)							{   return (daIS_F_INSTR_SYMBOL_IN_MEMIMM(f) || daIS_F_INSTR_SYMBOL_IN_IMM(f)); }

inline BOOL	daIS_REFERENCED(type_flags f)								{	return (daIS_F_FUNC_EXPORTED(f) || daIS_F_RELOC_XREF(f)); }





inline void daSET_ACCESSED_AS_DATA_ON_LEN(type_flags *f, ulong32 rva, int dlen)
{
	// set head
	f[rva]	|= DA_FLAG_HEAD | DA_FLAG_ACCESSED_AS_DATA;
	// set tail
	for (int i = 1; i < dlen; i++)
		f[rva+i] |= DA_FLAG_ACCESSED_AS_DATA| DA_FLAG_TAIL;
}



inline BOOL daIS_F_BB_INTERRUPTED(type_flags f)							{	return (f & DA_FLAG_BB_INTERRUPTED);	}
inline void daSET_F_BB_INTERRUPTED(type_flags *f)						{	*f |= 	DA_FLAG_BB_INTERRUPTED; }
inline void daSET_F_ACCESSED_AS_DATA(type_flags *f)						{	*f |= 	DA_FLAG_ACCESSED_AS_DATA; }
inline BOOL daIS_F_ACCESSED_AS_DATA(type_flags f)						{	return (f & DA_FLAG_ACCESSED_AS_DATA);	}
inline void daSET_F_PROSPECT(type_flags *f)								{	*f |= 	DA_FLAG_PROSPECT; }
inline BOOL daIS_F_PROSPECT(type_flags f)								{	return (f & DA_FLAG_PROSPECT);	}




inline void daSET_INSTR_ON_LEN(type_flags *f, ulong32 rva, int ilen)
{
	// set head
	f[rva]	|= DA_FLAG_ANALYZED | DA_FLAG_HEAD | DA_FLAG_INSTR;
	// set tail
	for (int i = 1; i < ilen; i++)
		f[rva+i] |= DA_FLAG_ANALYZED | DA_FLAG_TAIL;
}


inline void daSET_DATA_ON_LEN(type_flags *f, ulong32 rva, int dlen)
{
	// set head
	f[rva]	|= DA_FLAG_ANALYZED | DA_FLAG_HEAD | DA_FLAG_DATA;
	// set tail
	for (int i = 1; i < dlen; i++)
		f[rva+i] |= DA_FLAG_ANALYZED | DA_FLAG_TAIL | DA_FLAG_DATA;
}


inline ulong32 daFIND_HEAD(type_flags *f, ulong32 tail_rva)
{
	// assume it must always work
	while (!daIS_F_HEAD(f[--tail_rva]));
	return tail_rva;

}

typedef struct __bin_data
{
	ulong32					data_size;		// size of data (in mem)
	uchar					*data;			// file data (aligned ->sections etc)
	type_flags				*flags;			// for each byte
	struct __dinstr			**fast_instrs;	// pointer to dinstr structs for instructions

} _bin_data;

typedef ulong32 itype_flags;

typedef struct __dinstr
{
	
	//itype_flags				iflags;
	int8					len;						// len of instruction
	uchar					*data;						// ptr to data
	ulong32					rva_addr;					// original rva addr
	//int						emul_int;					// is this needed?

	int16					emul_int;


	ulong32					disit_flags;

	ulong32					objIMM_rva;		//	instruction links obj by IMM 
	ulong32					objMEMIMM_rva;				// instruction link by MEMIMM to some unknown object

	union
	{
		struct			__dinstr *linked_instr;				// linked instr (for example by jmp)
		ulong32			linked_instr_rva;
		//ulong32			objMEMIMM_rva;				// instruction link by MEMIMM to some unknown object
	};

	union
	{
		struct			__dinstr	*next_instr;				// instruction after this one (NULL if none)
		ulong32			next_instr_rva;
	};

} _dinstr;


#endif