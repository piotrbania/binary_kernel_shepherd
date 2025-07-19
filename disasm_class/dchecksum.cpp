#include "dchecksum.h"



DChecksum::DChecksum()
{
	this->max_size	=	DEFAULT_MAX_SIZE;
	this->bytes2crc	=	(uchar*)malloc(this->max_size);
	assert(this->bytes2crc);
	memset((void*)this->bytes2crc,0,this->max_size);


	this->weak_max_size	=	DEFAULT_MAX_SIZE;
	this->weak_bytes2crc	=	(uchar*)malloc(this->weak_max_size);
	assert(this->weak_bytes2crc);
	memset((void*)this->weak_bytes2crc,0,this->weak_max_size);

	this->reset_checksum();
}

DChecksum::~DChecksum()
{
	if (this->bytes2crc)
		free(this->bytes2crc);

	if (this->weak_bytes2crc)
		free(this->weak_bytes2crc);
}



/*
* Function resets the current checksum
*/

void DChecksum::reset_checksum()
{
	this->crc.crc		= 0;
	this->bytes_size	= 0;
	this->i_num			= 0;
	//this->crc.crc_weak	= 0;
	//this->symbols_num	= 0;

	this->weak_bytes_size		=	0;
	this->bytes2crc[0]			=	0;
	this->weak_bytes2crc[0]		=	0;
}

/*
* Function Add byte to the checksum buffer. 
*/

void DChecksum::add_byte_adler(uchar byte)
{
	this->bytes2crc[this->bytes_size++] = byte;

	if (this->bytes_size >= this->max_size)
	{
		// we need to realloc it to bigger size
		this->max_size	+= DEFAULT_MAX_SIZE;
		this->bytes2crc = (uchar*)realloc(this->bytes2crc, this->max_size);
		assert(this->bytes2crc);
	}

}


/*
* Function Add byte to the checksum buffer. 
*/

void DChecksum::add_byte_adler_weak(uchar byte)
{
	this->weak_bytes2crc[this->weak_bytes_size++] = byte;

	if (this->weak_bytes_size >= this->weak_max_size)
	{
		// we need to realloc it to bigger size
		this->weak_max_size	+= DEFAULT_MAX_SIZE;
		this->weak_bytes2crc = (uchar*)realloc(this->weak_bytes2crc, this->weak_max_size);
		assert(this->weak_bytes2crc);
	}

}







/*
* Function computes checksum from supplied bytes.
* Byte order is not important.
* We are using checksum from RFC1071.
*/

ulong32	DChecksum::compute_byte_checksum_adler(uchar *input, int input_size)
{
	ulong32 b = 0;
	ulong32 a = 0;
	#define MOD_ADLER 65521

	int		len	=	input_size;
	for (int index = 0; index < len; ++index)
    {
        a = (a + input[index]) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    return (b << 16) | a;
}


