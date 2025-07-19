#ifndef _DREFERENCES_H
#define _DREFERENCES_H


enum type_reference
{
	REF_IMM	=	0,
	REF_MEMIMM
};

typedef struct __reference_entry
{
	_dinstr			*instr;
	_dbasicblock	*bb;
} _reference_entry;


// for reference information
typedef hash_multimap<ulong32, _reference_entry*>		type_ReferenceMap;		
typedef pair<type_ReferenceMap::iterator,type_ReferenceMap::iterator> type_ReferencePair;


#endif