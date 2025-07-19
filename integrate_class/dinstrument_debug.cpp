
#include "danalyze.h"
#include "dintegrate.h"


/*
* This is an debug function emitted to almost every function entrypoint. 
* What is does is to executed DebugPrint with the function RVA string.
* use it only with ntkrnlpa
*/

int	DIntegrate::debug_instrument_function(_dfunction *func)
{
	if (!func->BBIList)
		return D_FAILED;


	type_flags	*flags	=	this->DA->BinData.flags;
	_bb_iext	*bbi	=	func->BBIList->front();
	_dbasicblock *bb	=	(_dbasicblock*)bbi->bb_org;
	_dinstr		*di		=	this->DA->get_dinstr_from_rva(bb->rva_start);
	assert(di);



	// check the symbol name if it starts with Dbg dont instrument it
	_sinfo			*SymbolInfo;
	SymbolInfo		=	this->DA->Symbols->get_symbol_info(bb->rva_start);
	if (SymbolInfo)
	{
		uchar	*sname	=	(uchar*)&SymbolInfo->name;
		if ((sname[0] == '_') || (sname[0] == '@'))
			sname++;


		//if (sname[0] = 'K')
		//	return D_FAILED;

		//if ((sname[0] != 'E') && (sname[1] == 'x'))
		//	return D_FAILED;


		//Dbg / Debug
		if (((sname[0] == 'D') && (sname[1] == 'b')) ||
			((sname[0] == 'D') && (sname[1] == 'e')))
		{
#if DI_DEBUG_IT == 1
			flog("%s: function at %08x is a DBG function (%s)\n",
				__FUNCTION__, 
				bb->rva_start,
				sname);
#endif
			return D_FAILED;
		}


#if DI_DEBUG_IT == 1
			flog("%s: trying to instrument function at %08x (%s)\n",
				__FUNCTION__, 
				bb->rva_start,
				sname);
#endif

	}
	

	// if function uses reloc it is not suitable
	// or it is a BB end
	type_flags	iflags	=	flags[di->rva_addr];
	if (daIS_F_BB_END(iflags) || daIS_F_INSTR_RELOCABLE_DATA_IN_MEMIMM(iflags) ||
		daIS_F_INSTR_RELOCABLE_DATA_IN_IMM(iflags))
	{
#if DI_DEBUG_IT == 1
		flog("%s: function %08x not suitable for instrumenting!\n",
			__FUNCTION__, bb->rva_start);
#endif
		return D_FAILED;
	}


	// add instrumentation
	// original_instruction
	// pushad
	// mov ebx,esp
	// mov eax,cr3
	// cmp eax,777h
	// jne bye
	// call over_string
	// function_name, 0
	// over_string:
	// call DbgPrint_rel
	// mov esp,ebx
	// bye: popad
	//00401000 >   8BDC           MOV EBX,ESP
	//00401002     8BE3           MOV ESP,EBX

	//00401004   . 0F21D8         MOV EAX,DR3                              ;  Privileged command
	//00401007   . 3D 77070000    CMP EAX,777
	//0040100C   . 75 00          JNZ SHORT 2.0040100E

	int		size_needed;
	uchar	*p;
	_instr_iext	*iext = bbi->InstrIExtList->front();

	/*
	00401003   81FC 00000080    CMP ESP,80000000
	00401009   7E 0A            JLE SHORT 2.00401015
	00401003   . 50             PUSH EAX
	00401004   . 0F21D8         MOV EAX,DR3                              ;  Privileged command
	00401007   . 3C 77          CMP AL,77
	00401009   . 75 01          JNZ SHORT 2.0040100C
	0040100B   . CC             INT3
	0040100C   > 58             POP EAX
	*/

	size_needed		=	di->len	+ 10 + 8;
	new_iext_data(iext, size_needed);
	p				= iext->data;
	memcpy(p, di->data, di->len);
	p		+= di->len;
	*p++			= 0x81;
	*p++			= 0xFC;
	*p++			= 0x00;
	*p++			= 0x00;
	*p++			= 0x00;
	*p++			= 0x80;
	*p++			= 0x7e;
	*p++			= 0x0a;








	*p++			=  0x50;
	*p++			=  0x0f;
	*p++			=  0x21;
	*p++			=  0xd8;
	*p++			=  0x3c;
	*p++			=  0x77;
	*p++			=  0x75;
	*p++			=  0x01;
	*p++			=  0xCC;
	*p++			=  0x58;
	iext->data_size	= size_needed;
	return D_OK;


















#define FUNC_STRING_SIZE 9+1
	size_needed		=	di->len + I_PUSHAD_LEN + I_CALL_LEN + FUNC_STRING_SIZE + I_CALL_LEN + I_POPAD_LEN + 4 + 10;
	new_iext_data(iext, size_needed);
	iext->data_size		=	size_needed;

	p			=	iext->data;
	char func_name[FUNC_STRING_SIZE+1];
	_snprintf(func_name, sizeof(func_name)-1, "%08x\n", bb->rva_start);

	// copy original instruction
	memcpy(p, di->data, di->len);
	p		+= di->len;
	sp_asmINSTR_PUSHAD(p);
	p		+= I_PUSHAD_LEN;

	*(uword*)p = 0xdc8b;
	p		+= 2;

	p[0] = 0x0F;
	p[1] = 0x21;
	p[2] = 0xD8;
	p[3] = 0x3D;
	p[4] = 0x77;
	p[5] = 0x07;
	p[6] = 0x00;
	p[7] = 0x00;
	p[8] = 0x75;
	p[9] = 5 + FUNC_STRING_SIZE + 5 + 2;
	p += 10;
	



	sp_asmINSTR_CALL(p);
	*(ulong32*)(p+1)	=	FUNC_STRING_SIZE;	// + I_CALL_LEN;
	p		+= I_CALL_LEN;

	// function string
	memcpy(p, (void*)&func_name, FUNC_STRING_SIZE);
	p	+= FUNC_STRING_SIZE;

	// call to debug print
	sp_asmINSTR_CALL(p);
	p		+= I_CALL_LEN;


	*(uword*)p = 0xe38b;
	p		+= 2;
	sp_asmINSTR_POPAD(p);
	p		+= I_POPAD_LEN;


	
	daSET_F_BB_EXT_DEBUG_FIX(&bbi->flags);





#if DI_DEBUG_IT == 1
			flog("%s: instrumented function at %08x\n",
				__FUNCTION__, 
				bb->rva_start);
#endif


	return D_OK;
}