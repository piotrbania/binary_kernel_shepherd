
#include "danalyze.h"
#include "dintegrate.h"



int			DIntegrate::debug_fix_func(_dfunction *func, _bb_iext *bbi, _instr_iext *iext, ulong32 iRVA)
{

	ulong32 f_addr = func->bb_start->rva_start;
	//if ((f_addr != 0x000AF5D0) && (f_addr != 0x0006D765))
	//	return D_FAILED;

	//if (f_addr != 0x000A34AF)
	//	return D_FAILED;

	// ok if this instruction is call 
	_dinstr	*di	=	iext->di_org;
	if (di->emul_int != CALL_0)
		return D_FAILED;


	//if (di->rva_addr != 0x000a3561)
	//	return D_FAILED;



	assert(iext->data[0] == 0xE8);
	_dfunction *f_dest = this->DA->find_function_by_rva(iext->di_org->linked_instr_rva);
	assert(f_dest);

	ulong32 f_dest_rva = f_dest->bb_start->rva_start;
	if (f_dest_rva != 0x00068090)
		return D_FAILED;



	flog("%s: [%d] FUNC=%08x repairing instruction %08x (newRVA=%08x) -> callTO: %08x\n", 
		__FUNCTION__, debug_repair_count, f_addr, di->rva_addr, iRVA, f_dest_rva);


	// now fix the call
	*(ulong32*)&iext->data[1]	= f_dest_rva - iRVA - 5;	


	debug_repair_count++;
	return D_OK;
}