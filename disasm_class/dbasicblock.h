#ifndef _DBASICBLOCK_H
#define _DBASICBLOCK_H


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
#include "disit_types.h"
#include "dchecksum.h"


#ifdef _BINSHEP
#include "dintegrate_structs.h"
#endif

using namespace std;
using namespace stdext;


typedef vector<struct __dbasicblock*>			type_BBList;
//typedef map<ulong32, struct __dbasicblock*>		type_BBMap;
typedef hash_map<ulong32, struct __dbasicblock*>		type_BBMap;



typedef vector<struct __dbasicblock*>	type_BBChildFunctions;
typedef vector<struct __dbasicblock*>	type_BBParents;
typedef vector<struct __dbasicblock*>	type_BBChilds;
typedef vector<struct __dbasicblock*>	type_BBMerged;


typedef uint8	bbtype_flags;
#define DA_FLAG_BB_MERGED			0x00000001		// basicblock was merged
#define DA_FLAG_BB_TODELETE			0x00000002		// basicblock needs to get deleted (because it was merged)
#define DA_FLAG_BB_MATCHED			0x00000004		// basicblock was matched
#define DA_FLAG_BB_MULTIPLEMATCH	0x00000008		// basicblock had multiple matches by checksum
#define DA_FLAG_BB_HARDMATCH		0x00000010		// basicblock hardcore match (by name or partial crc)
#define DA_FLAG_BB_FUNCTION_START	0x00000020		// basicblock is a function start
#define DA_FLAG_BB_HARDMATCH_WEAKB	0x00000040		// basicblock was matched, via weak byte sig (means that imm values were ignored)

#if DA_USE_SQL == 1
#define DA_FLAG_BB_SQLPROCESSED		0x00000080		// basicblock was already exported to sql
inline void daSET_F_BB_SQLPROCESSED(bbtype_flags *f)								{	*f |= 	DA_FLAG_BB_SQLPROCESSED;	}
inline BOOL daIS_F_BB_SQLPROCESSED(bbtype_flags f)									{	return (f & DA_FLAG_BB_SQLPROCESSED);	}
#endif



inline void daSET_F_BB_MERGED(bbtype_flags *f)								{	*f |= 	DA_FLAG_BB_MERGED;	}
inline void daSET_F_BB_TODELETE(bbtype_flags *f)							{	*f |= 	DA_FLAG_BB_TODELETE;}
inline void daSET_F_BB_MATCHED(bbtype_flags *f)								{	*f |= 	DA_FLAG_BB_MATCHED;}
inline void daSET_F_BB_MULTIPLEMATCH(bbtype_flags *f)						{	*f |= 	DA_FLAG_BB_MULTIPLEMATCH;}
inline void daSET_F_BB_HARDMATCH(bbtype_flags *f)							{	*f |= 	DA_FLAG_BB_HARDMATCH;}
inline void daSET_F_BB_FUNCTION_START(bbtype_flags *f)						{	*f |= 	DA_FLAG_BB_FUNCTION_START;}
inline void daSET_F_BB_HARDMATCH_WEAKB(bbtype_flags *f)						{	*f |= 	DA_FLAG_BB_HARDMATCH_WEAKB;}

inline BOOL daIS_F_BB_MERGED(bbtype_flags f)								{	return (f & DA_FLAG_BB_MERGED);	}
inline BOOL daIS_F_BB_TODELETE(bbtype_flags f)								{	return (f & DA_FLAG_BB_TODELETE);	}
inline BOOL daIS_F_BB_MATCHED(bbtype_flags f)								{	return (f & DA_FLAG_BB_MATCHED);	}
inline BOOL daIS_F_BB_HARDMATCH(bbtype_flags f)								{	return (f & DA_FLAG_BB_HARDMATCH);	}
inline BOOL daIS_F_BB_MULTIPLEMATCH(bbtype_flags f)							{	return (f & DA_FLAG_BB_MULTIPLEMATCH);	}
inline BOOL daIS_F_BB_HARDMATCH_WEAKB(bbtype_flags f)						{	return (f & DA_FLAG_BB_HARDMATCH_WEAKB);	}


inline BOOL daIS_F_BB_FUNCTION_START(bbtype_flags f)						{	return (f & DA_FLAG_BB_FUNCTION_START);	}
inline BOOL	da_WAS_MATCHED(bbtype_flags f)									{   return (daIS_F_BB_MATCHED(f) || daIS_F_BB_MULTIPLEMATCH(f) ||  daIS_F_BB_HARDMATCH(f)); }


inline	ulong32 SET_BASICBLOCK_NOTRESOLVED(ulong32 bb_addr)	{ return (bb_addr | 0x80000000); }
inline	BOOL	IS_BASICBLOCK_NOTRESOLVED(ulong32 bb_addr)	{ return (bb_addr & 0x80000000); }


#define get_list_size(x)	(x == 0? 0:x->size()) 

typedef struct __dbasicblock
{

	bbtype_flags	flags;
	ulong32			rva_start;		//	starting rva (first basicblock instruction)
	//ulong32			rva_end;		//  rva of last basicblock instruction


	_dcrc			crc;

	type_BBChildFunctions	*ChildFunctionsList;
	type_BBParents			*ParentsList;
	type_BBChilds			*ChildsList;			// never more	
	type_BBMerged			*MergedList;			// list of merged basicblocks (in order)


	__dbasicblock	*bb_matched;					// matched basicblock in another file

	// extensions for integrator
#ifdef _BINSHEP
	_bb_iext					*bb_iext;
	ulong32						rva_end;
	//uint16						shared_times;		// times the basicblock was shared among different
													// functions (=1 means normal)
#endif


} _dbasicblock;

#endif