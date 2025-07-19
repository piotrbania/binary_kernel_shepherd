#ifndef _DCHECKSUM_H
#define _DCHECKSUM_H

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <windows.h>

#include "disit_types.h"
#include "danalyze_options.h"


struct d
{
	union
	{

		// byte_crc:24;
		// (8 bitow na flagi)

		struct
		{
					unsigned	byte_crc:23;		// byte crc

					unsigned	uses_memimm_relocable:1;	// mem_imm is relocable
					unsigned	uses_imm:1;				// uses imm
					unsigned	uses_memimm:1;			// uses memimm
					//unsigned	uses_jcc:1;
					unsigned	uses_mem:1;
					unsigned	mem_act:1;
					unsigned    tttn:4;

					//unsigned kapa:8;

		};
		ulong32		first_32bit;
	};

			union
			{
				struct
				{
					unsigned	instr_num:8;		// how many instructions in basicblock
					unsigned	childs_num:8;		// how many child edges
					unsigned	parents_num:8;	// how many parents
					unsigned	child_func_num:8;	// how many child functions (executed by call*)
				};
				ulong32		desc_crc;
			};
};


// struct describing our checksum
typedef struct __dcrc
{
	union
	{
		d			crc_elements;
		ulong64		crc;
	};


	ulong32		crc_adler;		// strict checksum order depended from instruction bytes

#if DA_DIFF_USE_WEAKCRCMAP == 1
	ulong32		crc_weak;		// weak crc, does not include IMMs (from push) etc.
#endif


} _dcrc;


class DChecksum
{
	public:
		DChecksum();
		~DChecksum();

		void		reset_checksum();
		void		add_byte_adler(uchar byte);
		void		add_byte_adler_weak(uchar byte);

		inline		void add_byte_clean(uchar byte)			{ this->crc.crc_elements.byte_crc += byte; }
		inline		ulong32 get_byte_checksum(void)			{ return this->crc.crc_elements.byte_crc; }
		inline		void inc_instruction_counter(void)		{ this->i_num += 1; }
		inline		void set_instruction_counter(ulong32 i_num)	{ this->i_num = i_num; }

		//inline		void inc_symbols_counter(void)				{ this->symbols_num += 1; }
		//inline		void set_symbols_counter(ulong32 sym_num)	{ this->symbols_num = sym_num ; }	

		_dcrc		crc;
		ulong32		compute_byte_checksum_adler(uchar *input, int input_size);

		ulong64 compute_checksum(
			int		number_of_instructions,
			int		number_of_childs,
			int		number_of_parents,
			int		number_of_child_functions);


		inline		ulong32 compute_checksum_partial(
			int		number_of_childs,
			int		number_of_parents,
			int		number_of_child_functions)
		{
				_dcrc dcrc;
				dcrc.crc_elements.child_func_num	=	number_of_child_functions;
				dcrc.crc_elements.childs_num		=	number_of_childs;
				dcrc.crc_elements.parents_num		=	number_of_parents;
				dcrc.crc_elements.instr_num			=	this->i_num;
				//dcrc.crc_elements.symbols_num		=	this->symbols_num;
				return dcrc.crc_elements.desc_crc;
		};


		inline		_dcrc compute_checksum_full(
			int		number_of_childs,
			int		number_of_parents,
			int		number_of_child_functions)
		{
				_dcrc dcrc;

				dcrc.crc							=	0;
				dcrc.crc_adler						=	this->compute_byte_checksum_adler(this->bytes2crc, this->bytes_size);

#if DA_DIFF_USE_WEAKCRCMAP == 1
				dcrc.crc_weak						=	this->compute_byte_checksum_adler(this->weak_bytes2crc, this->weak_bytes_size);
#endif
				dcrc.crc_elements.first_32bit		=	crc.crc_elements.first_32bit;
				dcrc.crc_elements.child_func_num	=	number_of_child_functions;
				dcrc.crc_elements.childs_num		=	number_of_childs;
				dcrc.crc_elements.parents_num		=	number_of_parents;
				dcrc.crc_elements.instr_num			=	this->i_num;
				//dcrc.crc_elements.symbols_num		=	this->symbols_num;
				return dcrc;
		};


	private:
#define DEFAULT_MAX_SIZE 4096
		int			max_size;			// current max sizeo f byets2crc array
		uchar		*bytes2crc;	
		int			bytes_size;			// how many uploaded bytes to crc?


		int			weak_max_size;
		uchar		*weak_bytes2crc;
		int			weak_bytes_size;


		int			i_num;				// number of instructions
		//int			symbols_num;
		

};



#endif