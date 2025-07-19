
#include "danalyze.h"
#include "dintegrate.h"


/*
* FOR RET instrumentation is:
* push	usePAX {0/1}
* push	retIMM	{0-if none)
* call callback_RET
* original_ret
*
*
* in callback:
* * jmp over:
* 5bytes_reserved
* over:
* ret 8
*/
//0040100B  |. EB 05          JMP SHORT bin_inst.00401012
// 0040100B  \. C2 0800        RETN 8
// if PAX instrumentation is not enabled use ret


#if DI_USE_PAX == 1
unsigned char callback_RET_data[] = {  0xEB, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC2, 0x08, 0x00 };
#else
unsigned char callback_RET_data[] = {  0xEB, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3 };
#endif


/*
* FOR CALLI instrumentation is:
* 
* push dest
* call callback_CALLI
* original_call_instr			-> relocation added if needed
*
* So in temporary callback we put:
* jmp over:
* 5bytes_reserved
* over:
* ret 4
*/
unsigned char callback_CALLI_data[] = {
	 0xEB, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC2, 0x04, 0x00
};



/*
* FOR JMPI:
* instrumentation is:
* push dest
* call callback_JMPI
* So in temporary callback we put:
* jmp over:
* 5bytes_reserved
* over:
* add esp, 4
* ret
*/
unsigned char callback_JMPI_data[] = { 
	 0xEB, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x83, 0xC4, 0x04, 0xC3
};




/*
* Functions emits callbacks to callback mem.
*/

int	DIntegrate::generate_callbacks(void)
{

	int total_size				= sizeof(callback_JMPI_data) + sizeof(callback_CALLI_data) +
		sizeof(callback_RET_data);
	this->callback_mem			= new uchar[total_size];
	assert(this->callback_mem);
	memset((void*)this->callback_mem, 0, total_size);
	this->callback_mem_size	=	total_size;


	// copy RET callback
	this->rva_callback_RET		=	0;
	memcpy((void*)this->callback_mem, callback_RET_data, sizeof(callback_RET_data));

	// copy CALLI callback
	this->rva_callback_CALLI	=	sizeof(callback_RET_data);
	memcpy((void*)&this->callback_mem[this->rva_callback_CALLI], callback_CALLI_data, sizeof(callback_CALLI_data));

	// copy JMP callback
	this->rva_callback_JMPI	=	this->rva_callback_CALLI + sizeof(callback_CALLI_data);
	memcpy((void*)&this->callback_mem[this->rva_callback_JMPI], callback_JMPI_data, sizeof(callback_JMPI_data));

#if DI_DEBUG_IT == 1
	flog("%s: rva_callback_RET = %08x * rva_callback_CALLI = %08x * rva_callback_JMPI = %08x MEM_SIZE=%08x\n",
		__FUNCTION__,
		this->rva_callback_RET,
		this->rva_callback_CALLI,
		this->rva_callback_JMPI,
		this->callback_mem_size);

#endif

	return D_OK;
}