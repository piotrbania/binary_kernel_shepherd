#ifndef _DINTEGRATE_STRUCTS_H
#define _DINTEGRATE_STRUCTS_H

#include "disit_types.h"
#include "dbasicblock.h"
#include "dfuncs.h"


#include <vector>
using namespace std;

typedef uint16	bb_ext_type_flags;


#define DA_FLAG_BB_EXT_VISITED				0x000000001		// basicblock was visited by DFS
#define DA_FLAG_BB_EXT_INSTRUMENT_RET		0x000000002		// last instruction is ret and was instrumented
#define DA_FLAG_BB_EXT_INSTRUMENT_CALLI		0x000000004		// last call indirect, instrumented
#define DA_FLAG_BB_EXT_INSTRUMENT_JMPI		0x000000008		// last jmp indirect, instrumented
#define DA_FLAG_BB_EXT_EXTENDED_JCC			0x000000010		// last instruction was "short jcc" and was extended
#define DA_FLAG_BB_EXT_INSTRUMENT_CALLREL	0x000000020		// last instruction was call rel32 and was extended
#define DA_FLAG_BB_EXT_EXTENDED_JMP			0x000000040		// last instruction was "short jcc" and was extended
#define DA_FLAG_BB_EXT_REQUIRES_NFIX		0x000000080		// next block link must be fixed
#define DA_FLAG_BB_EXT_REQUIRES_JMPJCCFIX	0x000000100		// instruction is a JMP/JCC and requires to be fixed
#define DA_FLAG_BB_EXT_REDUNDANT_JMP		0x000000200		// jump is redundant (no need to emit it)
#define DA_FLAG_BB_EXT_INTERRUPTED			0x000000400		// block was interrupted (requires relocation addon)
#define DA_FLAG_BB_EXT_HOOKABLE				0x000000800		// basicblock is hookable
#define DA_FLAG_BB_EXT_RESTORECALL			0x000001000		// call must be restored to original function

#define DA_FLAG_BB_EXT_SHARED				0x000002000		// for antirop -> basicblock was shared

#define DA_FLAG_BB_EXT_DEBUG_FIX			0x000004000		// debug instrumentation



inline void daSET_F_BB_EXT_VISITED(bb_ext_type_flags *f)										{	*f |= 	DA_FLAG_BB_EXT_VISITED;	}
inline void daSET_F_BB_EXT_NOTVISITED(bb_ext_type_flags *f)										{	*f &= ~DA_FLAG_BB_EXT_VISITED;	}

inline void daSET_F_BB_EXT_INSTRUMENT_RET(bb_ext_type_flags *f)									{	*f |= 	DA_FLAG_BB_EXT_INSTRUMENT_RET;	}
inline void daSET_F_BB_EXT_INSTRUMENT_CALLI(bb_ext_type_flags *f)								{	*f |= 	DA_FLAG_BB_EXT_INSTRUMENT_CALLI;	}
inline void daSET_F_BB_EXT_INSTRUMENT_JMPI(bb_ext_type_flags *f)								{	*f |= 	DA_FLAG_BB_EXT_INSTRUMENT_JMPI;	}
inline void daSET_F_BB_EXT_EXTENDED_JCC(bb_ext_type_flags *f)									{	*f |= 	DA_FLAG_BB_EXT_EXTENDED_JCC;	}
inline void daSET_F_BB_EXT_INSTRUMENT_CALLREL(bb_ext_type_flags *f)								{	*f |= 	DA_FLAG_BB_EXT_INSTRUMENT_CALLREL;	}
inline void daSET_F_BB_EXT_EXTENDED_JMP(bb_ext_type_flags *f)									{	*f |= 	DA_FLAG_BB_EXT_EXTENDED_JMP;	}
inline void daSET_F_BB_EXT_REDUNDANT_JMP(bb_ext_type_flags *f)									{	*f |= 	DA_FLAG_BB_EXT_REDUNDANT_JMP;	}
inline void daSET_F_BB_EXT_INTERRUPTED(bb_ext_type_flags *f)									{	*f |= 	DA_FLAG_BB_EXT_INTERRUPTED;	}
inline void daSET_F_BB_EXT_HOOKABLE(bb_ext_type_flags *f)										{	*f |= 	DA_FLAG_BB_EXT_HOOKABLE;	}
inline void daSET_F_BB_EXT_NOTHOOKABLE(bb_ext_type_flags *f)									{	*f &= ~DA_FLAG_BB_EXT_HOOKABLE;	}
inline void daSET_F_BB_EXT_DEBUG_FIX(bb_ext_type_flags *f)										{	*f |= DA_FLAG_BB_EXT_DEBUG_FIX;	}
inline void daSET_F_BB_EXT_RESTORECALL(bb_ext_type_flags *f)									{	*f |= DA_FLAG_BB_EXT_RESTORECALL;	}




inline void daSET_F_BB_EXT_REQUIRES_NFIX(bb_ext_type_flags *f)									{	*f |= 	DA_FLAG_BB_EXT_REQUIRES_NFIX; }
inline void daSET_F_BB_EXT_REQUIRES_JMPJCCFIX(bb_ext_type_flags *f)								{	*f |= 	DA_FLAG_BB_EXT_REQUIRES_JMPJCCFIX; }






inline BOOL daIS_F_BB_EXT_VISITED(bb_ext_type_flags f)												{	return (f & DA_FLAG_BB_EXT_VISITED);	}

inline BOOL daIS_F_BB_EXT_INSTRUMENT_RET(bb_ext_type_flags f)										{	return (f & DA_FLAG_BB_EXT_INSTRUMENT_RET);	}
inline BOOL daIS_F_BB_EXT_INSTRUMENT_CALLI(bb_ext_type_flags f)										{	return (f & DA_FLAG_BB_EXT_INSTRUMENT_CALLI);	}
inline BOOL daIS_F_BB_EXT_INSTRUMENT_JMPI(bb_ext_type_flags f)										{	return (f & DA_FLAG_BB_EXT_INSTRUMENT_JMPI);	}
inline BOOL daIS_F_BB_EXT_EXTENDED_JCC(bb_ext_type_flags f)											{	return (f & DA_FLAG_BB_EXT_EXTENDED_JCC);	}
inline BOOL daIS_F_BB_EXT_INSTRUMENT_CALLREL(bb_ext_type_flags f)									{	return (f & DA_FLAG_BB_EXT_INSTRUMENT_CALLREL);	}
inline BOOL daIS_F_BB_EXT_EXTENDED_JMP(bb_ext_type_flags f)											{	return (f & DA_FLAG_BB_EXT_EXTENDED_JMP);	}
inline BOOL daIS_F_BB_EXT_REDUNDANT_JMP(bb_ext_type_flags f)										{	return (f & DA_FLAG_BB_EXT_REDUNDANT_JMP);	}
inline BOOL daIS_F_BB_EXT_INTERRUPTED(bb_ext_type_flags f)											{	return (f & DA_FLAG_BB_EXT_INTERRUPTED); }
inline BOOL daIS_F_BB_EXT_HOOKABLE(bb_ext_type_flags f)												{	return (f & DA_FLAG_BB_EXT_HOOKABLE); }
inline BOOL daIS_F_BB_EXT_DEBUG_FIX(bb_ext_type_flags f)											{	return (f & DA_FLAG_BB_EXT_DEBUG_FIX); }
inline BOOL daIS_F_BB_EXT_RESTORECALL(bb_ext_type_flags f)											{	return (f & DA_FLAG_BB_EXT_RESTORECALL); }



inline BOOL daIS_F_BB_EXT_REQUIRES_NFIX(bb_ext_type_flags f)										{	return (f & DA_FLAG_BB_EXT_REQUIRES_NFIX); }
inline BOOL daIS_F_BB_EXT_REQUIRES_JMPJCCFIX(bb_ext_type_flags f)									{	return (f & DA_FLAG_BB_EXT_REQUIRES_JMPJCCFIX); }


inline BOOL daIS_F_BB_EXT_REQUIRE_CALLBACK_FIX(bb_ext_type_flags f)										{	return (f & (DA_FLAG_BB_EXT_INSTRUMENT_RET | DA_FLAG_BB_EXT_INSTRUMENT_CALLI | DA_FLAG_BB_EXT_INSTRUMENT_JMPI));	}



inline void daSET_F_BB_EXT_SHARED(bb_ext_type_flags *f)												{	*f |= 	DA_FLAG_BB_EXT_SHARED;	}
inline BOOL daIS_F_BB_EXT_SHARED(bb_ext_type_flags f)												{	return (f & DA_FLAG_BB_EXT_SHARED); }





// function extended flags -----------------------------------------
typedef uint8	func_ext_type_flags;

#define DA_FLAG_FUNC_EXT_FORBIDDEN				0x000000001		// function is forbidden to hook
#define DA_FLAG_FUNC_EXT_RESTORECALL			0x000000002		// function must be executed at natice location

inline BOOL daIS_F_FUNC_EXT_FORBIDDEN(func_ext_type_flags f)										{	return (f & DA_FLAG_FUNC_EXT_FORBIDDEN);	}
inline void daSET_F_FUNC_EXT_FORBIDDEN(func_ext_type_flags *f)										{	*f |= 	DA_FLAG_FUNC_EXT_FORBIDDEN;	}

inline BOOL daIS_F_FUNC_EXT_RESTORECALL(func_ext_type_flags f)										{	return (f & DA_FLAG_FUNC_EXT_RESTORECALL);	}
inline void daSET_F_FUNC_EXT_RESTORECALL(func_ext_type_flags *f)									{	*f |= 	DA_FLAG_FUNC_EXT_RESTORECALL;	}




/*
* instruction extension for integration purposes
*/

typedef struct __instr_iext
{
	_dinstr				*di_org;		// original instruction pointer
	uchar				*data;
	uint8				data_size;

} _instr_iext;


typedef vector<_instr_iext*>	type_InstrIExtList;





/*
* basic block extension for integration purposes
*/
typedef struct __bb_iext
{
	bb_ext_type_flags		flags;
	type_InstrIExtList		*InstrIExtList;

	void					*bb_org;
	ulong32					rva_new;
	ulong32					size;			// size of all instructions in the basicblock
	uint16					DFSInTime;		// 16bits should be enough

	__bb_iext				*bbi_linked;
	__bb_iext				*bbi_next;

} _bb_iext;

typedef vector <_bb_iext*>	type_BBIExtList;


typedef vector <_bb_iext*>	type_BBIExtCallRelList;		// list of basicblocks ended by CALL REL
typedef vector <ulong32>	type_RelocsList;			// each ulong32 reprsents a rva
typedef vector <ulong32>	type_BlackList;				// rvas of function that cannot be hooked

typedef vector <_dinstr*>	type_DICollisions;			// patched calls multiple times

#define CALLBACK_TYPE_RET				0
#define CALLBACK_TYPE_CALLI				1
#define CALLBACK_TYPE_JMPI				2

typedef struct __callback_location
{
	ulong32		rva_addr;
	uint8		type;							// type of callback
} _callback_location;

typedef vector <_callback_location*>	type_CallbacksList;


// this stuff could be done in disit/asmit, but it is faster this way
// reffer to disasm.h for the values


inline void sp_asmINSTR_LONG_JCC(uchar *data, uchar tttn)				{ *(uchar*)data = 0x0F; *(uchar*)(data+1) = 0x80 | tttn; } 
inline void sp_asmINSTR_DEC_ECX(uchar *data)							{ *(uchar*)data = 0x49;	} 
inline void sp_asmINSTR_OR_ECXECX(uchar *data)							{ *(uword*)data = 0xC909; }
inline void sp_asmINSTR_SHORT_JMP(uchar *data)							{ *(uchar*)data = 0xEB; }
inline void sp_asmINSTR_CALLFAR(uchar *data)							{ *(uword*)data = 0x15FF; }
inline void sp_asmINSTR_LONG_JMP(uchar *data)							{ *(uchar*)data = 0xE9; }
inline void sp_asmINSTR_RET(uchar *data)								{ *(uchar*)data = 0xC3; }
inline void sp_asmINSTR_PUSHAD(uchar *data)								{ *(uchar*)data = 0x60; }
inline void sp_asmINSTR_POPAD(uchar *data)								{ *(uchar*)data = 0x61; }
inline void sp_asmINSTR_CALL(uchar *data)								{ *(uchar*)data = 0xE8; }



// gets tttn from opcode, typicall usage for small jcc jumps
inline uchar sp_asmGET_TTTN(uchar opcode)								{ return (opcode & 0x0F); }
inline uchar sp_asmGET_REG(uchar opcode)								{ return (opcode & 0x07); }

inline void sp_asmINSTR_PUSH_VALUE(uchar *data, ulong32 val)			{ *(uchar*)data = 0x68; *(ulong32*)(data+1) = val; }
inline void sp_asmINSTR_PUSH_MEM(uchar *data, uchar *mem, int mlen)		{ *(uchar*)data = 0xFF; memcpy((void*)(data+1),mem,mlen); *(uchar*)(data+1) &= 0xC7; *(uchar*)(data+1) |= 0x30; } 
inline void sp_asmINSTR_PUSH_REG(uchar *data, int reg)					{ *(uchar*)data = (0x50 | (reg & 0x07)); }	// RR_EAX
inline void sp_asmINSTR_ADD_REG_S(uchar *data, int reg, int8 val)		{ *(uchar*)data = 0x83; *(uchar*)(data+1) = 0xC0 | reg; *(uchar*)(data+2) = val; }
inline void sp_asmINSTR_SUB_REG_S(uchar *data, int reg, int8 val)		{ *(uchar*)data = 0x83; *(uchar*)(data+1) = 0xE8 | reg; *(uchar*)(data+2) = val; }

inline void sp_asmTEST_EAX_IMM32(uchar *data, ulong32 imm32)			{ *(uchar*)data = 0xA9; *(ulong32*)(data+1) = imm32; }





/* hardcoded ASM stuff for x86 arch */
#define					I_TEST_EAX_IMM32_LEN				5

#define					I_SHORT_JMP_LEN						2
#define					I_SHORT_JCC_LEN						2
#define					I_LONG_JCC_LEN						6
#define					I_CALL_LEN							5
#define					I_JMP_LEN							5
#define					I_DEC_LEN							1
#define					I_OR_REGREG_LEN						2
#define					I_CALLFAR_LEN						6
#define					I_RET_LEN							1
#define					I_PUSHAD_LEN						1
#define					I_POPAD_LEN							1



#define					I_ADD_REG_S							3
#define					I_SUB_REG_S							3
#define					I_PUSH_VALUE_LEN					5
#define					I_PUSH_REG_LEN						1
#define					I_POP_REG_LEN						1

#define					I_CALL_ADDR_OFF						1			// rel.off after 1 bytes
#define					I_LONG_JCC_ADDR_OFF					2			// rel.offset after 2 bytes
#define					I_SHORT_JCC_ADDR_OFF				1			// rel.off after 1 bytes

#endif