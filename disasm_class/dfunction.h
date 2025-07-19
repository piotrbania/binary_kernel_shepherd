#ifndef _DFUNCTION_H
#define _DFUNCTION_H


#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <windows.h>
#include <math.h>
#include <list>
#include <map>
#include <vector>
#include <hash_map>

#include "disit_types.h"
#include "dchecksum.h"
#include "dbasicblock.h"
#include "symbol_class.h"

using namespace std;
using namespace stdext;

#ifdef _BINSHEP
#include "dintegrate_structs.h"
#endif


typedef struct __dfunction
{
	_dbasicblock	*bb_start;
	_dbasicblock	*bb_end;


#ifdef _BINSHEP
	func_ext_type_flags		flags;
	type_BBIExtList			*BBIList;
	//type_BBList		*BBList;
#endif


	_sinfo			*SymbolInfo;
} _dfunction;




typedef vector<_dfunction*>					type_FunctionList;
typedef hash_map<ulong32, _dfunction*>		type_FunctionMap;


#endif