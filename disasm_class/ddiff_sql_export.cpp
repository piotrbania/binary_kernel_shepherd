
#include "ddiff.h"


#if DA_USE_SQL == 1

/* 
* Functions performs bindiff, and exports all the results&necessary data to sql
*/

int	DDiff::diff_and_export2sql(fileinfo_data *FileData1, fileinfo_data *FileData2)
{
	DAnalyze	*DA1, *DA2;

	this->DiffSql	=	new DDiffSqlExport;
	

	// launch the analyzers
	DA1			=	new DAnalyze;
	DA1->LoadPeFile((char*)FileData1->file_path);
	DA1->engine_run();
	DA1->close_symbols();
	DA2			=	new DAnalyze;
	DA2->LoadPeFile((char*)FileData2->file_path);
	DA2->engine_run();
	DA2->close_symbols();

	// set the objects
	this->set_src_dest_objects(DA1, DA2);
	this->compare_basicblocks();


	this->DiffSql->set_diff_source(this);
	this->DiffSql->setup(FileData1, FileData2);





	delete DA1;
	delete DA2;
	delete this->DiffSql;


	return D_OK;
}

DDiffSqlExport::DDiffSqlExport()
{
	this->Diff	= NULL;
	this->DA1	= NULL;
	this->DA2	= NULL;

}

DDiffSqlExport::~DDiffSqlExport()
{
}


/*
* Function exports the data gathered by BinDiff to SQL database
* Source object (Diff) must be set before using this function.
*/

int	DDiffSqlExport::setup(fileinfo_data *FileData1, fileinfo_data *FileData2)
{
	char		*file_name;


	// set the variables first
	this->FileData1	=	FileData1;
	this->FileData2	=	FileData2;

	// firstly make the magic number
	// second name is always the same
	file_name	=	strrchr(this->FileData1->file_path, '\\');
	assert(file_name);
	file_name++;


	// setup sql connection
	if (this->Sql.sp_sql_init() == D_FAILED)
		return D_FAILED;


	// check if the files werent diffed already
	// if so delete the tables from the database
	this->check_and_clear_previous();


	// now insert new modules
	this->m1_id = this->insert_module(
					FileData1->moduleOS,
					file_name,
					DA1->o_imagebase,
					DA1->o_filesize,
					FileData1->version,
					DA1->InstrList.size(),
					DA1->BasicBlockList.size(),
					DA1->seconds_elapsed_disassembly,
					DA1->seconds_elapsed_basicblocks);

	this->m2_id = this->insert_module(
					FileData2->moduleOS,
					file_name,
					DA2->o_imagebase,
					DA2->o_filesize,
					FileData2->version,
					DA2->InstrList.size(),
					DA2->BasicBlockList.size(),
					DA2->seconds_elapsed_disassembly,
					DA2->seconds_elapsed_basicblocks);



	// now insert the main diff entry
	this->insert_dentry(
		FileData1->moduleOS,
		this->m1_id,
		this->m2_id,
		Diff->seconds_elapsed_diff);


//	this->insert_module(
//		"kupajda",
//		0x1,
//		0x2, "ver 0", 3, 4, 0.1f, 0.2f);


	this->export_basicblocks();
	this->export_objs();
	return D_OK;
}

/*
* Function checks if tables for this diff (two exact files) already exist.
* If so they are delated. 
*/

int	DDiffSqlExport::check_and_clear_previous(void)
{
	ulong32		magic_crc;

	char		magic_buffer[MAX_PATH];
	char		*file_name1;

	// firstly make the magic number
	// second name is always the same
	file_name1	=	strrchr(this->FileData1->file_path, '\\');
	assert(file_name1);
	file_name1++;


	// compute magic buffer
	_snprintf(magic_buffer, sizeof(magic_buffer)-1, 
		"%s %s %s", 
		file_name1,
		this->FileData1->version,
		this->FileData2->version);

	// compute the magic crc
	magic_crc	=	ArrayCRC32((char*)&magic_buffer, strlen(magic_buffer));
	this->magic_crc = magic_crc;

	// now send a query to sql, if such diff is already found delete it
	if (this->get_dentry(magic_crc) == D_FAILED)
	{
#if DA_DEBUG_IT == 1
		flog("%s: previous SQL diff entry for %s (%s -> %s) was not found\n",
			__FUNCTION__,
			file_name1,
			this->FileData1->version,
			this->FileData2->version);
#endif
		return D_FAILED;		// no results

	}

	// seems we have those diff results already, so it is time
	// to delete them, to do so we need to grab the id first
	// row[0] = id
	// row[1] = patched_module_id
	// row[2] = notpatched_module_id

#if DA_DEBUG_IT == 1
		flog("%s: previous SQL diff entry for %s (%s -> %s) was found, now deleting it\n",
			__FUNCTION__,
			file_name1,
			this->FileData1->version,
			this->FileData2->version);
#endif


	// delete the dentry
	int	p_module_id		=	atoi(row[1]);
	int np_module_id	=	atoi(row[2]);
	mysql_free_result(res);

	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_DELETE_DENTRY, magic_crc);
	this->Sql.sp_sql_send(request);

	this->delete_module_data(p_module_id);
	this->delete_module_data(np_module_id);

	return D_OK;
}

/*
* Function prompts SQL for previous Diff results with magic_crc.
*/

int DDiffSqlExport::get_dentry(ulong32 magic_crc)
{
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_FIND_DENTRY, magic_crc);
	this->Sql.sp_sql_send(request);
	res		= mysql_use_result(&this->Sql.mysql);
	assert(res);
	row		= mysql_fetch_row(res);
	
	// entry not found, so nothing to delete 
	if (!row)
	{
		mysql_free_result(res);
		return D_FAILED;
	}

	return D_OK;
}



/*
* Function delates all tables which are used by moduleID.
*/

int	DDiffSqlExport::delete_module_data(int id)
{
	// it appears that MySQL refues to execute multiple drop commands at once :(
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_DELETE_DMODULE_DATA1,id);
	this->Sql.sp_sql_send(request);
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_DELETE_DMODULE_DATA2,id);
	this->Sql.sp_sql_send(request);
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_DELETE_DMODULE_DATA3,id);
	this->Sql.sp_sql_send(request);
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_DELETE_DMODULE_DATA4,id);
	this->Sql.sp_sql_send(request);
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_DELETE_DMODULE_DATA5,id);
	this->Sql.sp_sql_send(request);
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_DELETE_DMODULE_DATA6,id);
	this->Sql.sp_sql_send(request);
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_DELETE_DMODULE_DATA7,id);
	this->Sql.sp_sql_send(request);
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_DELETE_DMODULE_DATA8,id);
	this->Sql.sp_sql_send(request);
	

	return D_OK;
}


/*
* Function insert modules to the dmodules table, and create others tables
* for this module id.
*/




int DDiffSqlExport::insert_module(	
								type_moduleOS moduleOS,
								char *module_name, 
								ulong32 module_imagebase, 
								ulong32 module_filesize,
								char *module_version,
								int number_of_instructions, 
								int number_of_basicblocks,
								double seconds_elapsed_disasm,
								double seconds_elapsed_basicblocks)
{

	int			entry_id;
	ulong32		id_crc;
	char		id_crc_buff[32];

	_snprintf(id_crc_buff, sizeof(id_crc_buff)-1, "%08x %s",
		this->magic_crc,
		module_version);


	id_crc	=	ArrayCRC32((char*)&id_crc_buff, strlen(id_crc_buff));

	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_INSERT_TMODULE,
		id_crc,
		moduleOS,
		module_name,
		module_imagebase,
		module_filesize,
		module_version,
		number_of_instructions,
		number_of_basicblocks,
		seconds_elapsed_disasm,
		seconds_elapsed_basicblocks);
	this->Sql.sp_sql_send(request);

	// so it was inserted now, now we need to get it's ID number
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_FIND_TMODULE, id_crc);
	this->Sql.sp_sql_send(request);

	// it should always find something
	res		= mysql_use_result(&this->Sql.mysql);
	assert(res);
	row		= mysql_fetch_row(res);
	assert(row);

	// get the id -> row[0]
	entry_id	=	atoi(row[0]);
	mysql_free_result(res);


	// time to create rest of the tables
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_CREATE_TINSTRUCTIONS, entry_id);
	this->Sql.sp_sql_send(request);
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_CREATE_TBASICBLOCKS, entry_id);
	this->Sql.sp_sql_send(request);
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_CREATE_TBASICBLOCKS_CHILDS, entry_id);
	this->Sql.sp_sql_send(request);
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_CREATE_TBASICBLOCKS_PARENTS, entry_id);
	this->Sql.sp_sql_send(request);
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_CREATE_TOBJECTS, entry_id);
	this->Sql.sp_sql_send(request);
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_CREATE_TBASICBLOCKS_MERGED, entry_id);
	this->Sql.sp_sql_send(request);
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_CREATE_TTHREATLEVEL, entry_id);
	this->Sql.sp_sql_send(request);



	
	return entry_id;
}



/*
* Function adds new diff entry to the SQL database.
*/

int	DDiffSqlExport::insert_dentry(	
								type_moduleOS moduleOS,  
								int patched_module_id,
								int notpatched_module_id,
								double seconds_elapsed_diff)
{

	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_INSERT_TMAIN,
		this->magic_crc,
		moduleOS,
		patched_module_id,
		notpatched_module_id,
		 seconds_elapsed_diff,
		 this->Diff->debug_single_num,
		 this->Diff->debug_multiple_num,
		 this->Diff->debug_none_num);

	this->Sql.sp_sql_send(request);


	return D_OK;
}


/*
* Function sets the source for diff results exports
* (initialized the Diff class pointer)
*/

void DDiffSqlExport::set_diff_source(DDiff	*Diff)
{
	this->Diff	=	Diff;
	this->DA1   =	Diff->Analyze1;
	this->DA2   =	Diff->Analyze2;

}



/*
* Function exports basicblocks, instruction + additional data to sql.
* Please note that only basicblocks from function that consider to be
* changed are exported. I still dunno perhaps we should only limit
* it to basicblocks that are changed (unmatched).
*/

int	 DDiffSqlExport::export_basicblocks(void)
{
	type_FunctionMap::iterator it;

	// travel all the unmatched functions
	for (it = Diff->UmatchedFunctionsMap.begin();
		it != Diff->UmatchedFunctionsMap.end(); it++)
	{
		_dfunction *df = (*it).second;
		this->export_basicblocks_do(df->bb_start, TRUE);
		
		if (df->bb_start->bb_matched)
		{
			this->export_basicblocks_do(df->bb_start->bb_matched, FALSE);
		}

	}

	return D_OK;
}


/*
* Function travels all the basicblocks in the function
* starting from bb_start
*/

int	 DDiffSqlExport::export_basicblocks_do(_dbasicblock *bb_start, BOOL export_matched)
{
	_dbasicblock			*bb, *bb_temp;

	type_BBList				FutureBBs;
	type_BBMap				VisitedBBs;
	type_BBMap::iterator	it;

	VisitedBBs.clear();
	FutureBBs.clear();

	FutureBBs.push_back(bb_start);

	int counter = 0;

	for (;;)
	{
		if (FutureBBs.empty())
			break;

		bb	=	FutureBBs.back();
		FutureBBs.pop_back();

		// check if it was already processed
		it	=	VisitedBBs.find(bb->rva_start);
		if(it != VisitedBBs.end())
			continue;

		
	

		// not processed so add it to the map
		VisitedBBs.insert(make_pair<ulong32,_dbasicblock*>(bb->rva_start,bb));


		
		
		// if it has childs add them to the future list
		if (bb->ChildsList)
		{
			for (int i = 0; i < bb->ChildsList->size(); i++)
			{
				bb_temp = (*bb->ChildsList)[i];

				if (!IS_BASICBLOCK_NOTRESOLVED((ulong32)bb_temp))
					FutureBBs.push_back(bb_temp);
			}
		}


		// if this is for DA1
		if (export_matched)
		{
			// debug only
			//flog("DEBUG: *** %s: bb_rva = %08x\n", __FUNCTION__, bb->rva_start);

			// ok we can now export this basicblock information
			if ((!daIS_F_BB_MATCHED(bb->flags) && !daIS_F_BB_MULTIPLEMATCH(bb->flags)))
			{
				this->export_this_basicblock(bb, this->DA1, this->m1_id, TRUE);
			}
			else
				this->export_this_basicblock(bb, this->DA1, this->m1_id);

		
			// check if it was matched
			if (bb->bb_matched)
			{
				// if some export the mirrored one too
				this->export_this_basicblock(bb->bb_matched, this->DA2, this->m2_id);



			}

			// debug only
			//flog("DEBUG_RET: *** %s: bb_rva = %08x\n", __FUNCTION__, bb->rva_start);

		}
		else
		{
			// debug only
			//flog("DEBUG: *** %s: bb_rva2 = %08x\n", __FUNCTION__, bb->rva_start);

			// we are exporting the function from the unpatched file now
			// so no need to export matched blocks again
			this->export_this_basicblock(bb, this->DA2, this->m2_id);
			if (bb->bb_matched)
			{
				this->export_this_basicblock(bb->bb_matched, this->DA1, this->m1_id);
			}
			// debug only
			//flog("DEBUG_RET: *** %s: bb_rva2 = %08x\n", __FUNCTION__, bb->rva_start);

		}


	} // for (;;)


	return D_OK;
}


/*
* Export basicblocks and instruction information to SQL
*/

int	DDiffSqlExport::export_this_basicblock(_dbasicblock *bb, DAnalyze *DA, int id, BOOL find_objs)
{

	char	itext[256];
	char	ibytes[64];
	char	bb_name[46];

	int		request_size	=	0;
	char	single_request[512];


	_sinfo	*symbol;

	BOOL		is_function = FALSE;
	type_flags	*flags	=	DA->BinData.flags;
	//_dinstr		*di		=	this->DA1->get_dinstr_from_rva(bb->rva_start);
	//assert(di);


	itext[0]	= 0;
	ibytes[0]	= 0;
	bb_name[0]  = 0;

#define send_and_clear(x)	{ this->Sql.sp_sql_send(x); this->Sql.sp_sql_clear_results(); }


	this->request[0] = 0;

	// already processed
	if (daIS_F_BB_SQLPROCESSED(bb->flags))
		return D_FAILED;

	
				// debug
//				bp(bb->rva_start,		0x0000CA67); //0x0000CA73);


	daSET_F_BB_SQLPROCESSED(&bb->flags);

	// if this is a function mark it
	if (daIS_F_FUNCTION_START(flags[bb->rva_start]))
		is_function = TRUE;

	if (daIS_F_HAS_SYMBOL(flags[bb->rva_start]))
	{
		symbol = DA->Symbols->get_symbol_info(bb->rva_start);
		strcpy((char*)&bb_name, symbol->name);

	}

	ulong32 bb_end_rva	=	NULL;




	// export all instructions till BB end
	for (int j = bb->rva_start; ; j++)
	{	
		_dinstr	*di = DA->get_dinstr_from_rva(j);
		assert(di);
		//this->debug_show_instruction(j);
		
		//rva_addr, len, iflags, instr_type, obj_dest(BIG), obj_src(BIG), 
		// obj_IMM_rva, obj_MEMIMM_rva, disit_flags, itext, ibytes, 

		if (find_objs)
		{
			this->get_instr_objs(j, DA);
		}


		ibytes[0] = 0;
		for (int k = 0; k < di->len; k++)
			_snprintf(ibytes, sizeof(ibytes)-1, "%s %02x", ibytes, di->data[k]);

		DA->get_instruction_text(j, (char*)&itext);
		this->decorate_instr_line(j, (char*)&itext, DA);

		_snprintf(single_request, sizeof(single_request)-1, SQL_DB_SQL_INSERT_TINSTRUCTION,
			id,
			j,
			di->len,
			flags[j],
			di->emul_int,
			(ulong64)NULL,
			(ulong64)NULL,
			di->objIMM_rva,
			di->objMEMIMM_rva,
			di->disit_flags,
			(char*)&itext,
			(char*)&ibytes);




		// compute multiple SQL insert in one command
		if ((request_size + strlen(single_request)) >= (MAX_SQL_REQUEST_SIZE-1))
		{

			// debug only
			/*
			if (bb->rva_start == 0x000b46a0)
			{
				flog("DEBUG: %08x\n", j);
				flog_plain(this->request);
			}
			*/

			// send this one and continue
			send_and_clear(request);
			memset((void*)&this->request, 0, MAX_SQL_REQUEST_SIZE);
			request_size	=	0;
		}

		// add this string
		strcat((char*)&this->request, (char*)&single_request);
		request_size	+=	strlen((char*)&single_request);


		j	+= di->len - 1;

		if (daIS_F_BB_END(flags[di->rva_addr]))
		{
			bb_end_rva = j + 1;
			break;
		}

	} // for all bb instructions


//	bp(bb->rva_start, 	0x000b46a0);

	if (request_size)
		send_and_clear(request);



	// export childs
	
		//bp(bb->rva_start, 0x0000CA67 );//0x0000CA73);


	if (bb->ChildsList)
	{
		for (int i = 0; i < bb->ChildsList->size(); i++)
		{
			_dbasicblock *bb_temp	=	(*bb->ChildsList)[i];
			if (IS_BASICBLOCK_NOTRESOLVED((ulong32)bb_temp))
				continue;

			_snprintf(request, sizeof(request)-1, SQL_DB_SQL_INSERT_TBASICBLOCKS_CHILDS,
					id,
					bb->rva_start,
					bb_temp->rva_start);
			send_and_clear(request);

		}
	}

	// export parents
	if (bb->ParentsList)
	{
		for (int i = 0; i < bb->ParentsList->size(); i++)
		{
			_dbasicblock *bb_temp	=	(*bb->ParentsList)[i];
			if (IS_BASICBLOCK_NOTRESOLVED((ulong32)bb_temp))
				continue;

			_snprintf(request, sizeof(request)-1, SQL_DB_SQL_INSERT_TBASICBLOCKS_PARENTS,
					id,
					bb->rva_start,
					bb_temp->rva_start);
			send_and_clear(request);

		}
	}


	// export merged blocks
	if (bb->MergedList)
	{
		for (int i = 0; i < bb->MergedList->size(); i++)
		{
			_dbasicblock *bb_temp	=	(*bb->MergedList)[i];
			if (IS_BASICBLOCK_NOTRESOLVED((ulong32)bb_temp))
				continue;

			_snprintf(request, sizeof(request)-1, SQL_DB_SQL_INSERT_TBASICBLOCKS_MERGED,
					id,
					bb->rva_start,
					bb_temp->rva_start);
			send_and_clear(request);

			this->export_this_basicblock(bb_temp, DA, id, find_objs);
		}
	}



	// now store the basicblock
	// rva_start, rva_end, flags, bb_matched, crc_byte_strict, crc_byte, crc_cfg, is_function, name

	ulong32 matched_rva	= (bb->bb_matched == 0? 0: bb->bb_matched->rva_start);
	_snprintf(request, sizeof(request)-1, SQL_DB_SQL_INSERT_TBASICBLOCK,
		id,
		bb->rva_start,
		bb_end_rva,
		bb->flags,
		matched_rva,
		bb->crc.crc_adler,
		bb->crc.crc_elements.first_32bit,
		bb->crc.crc_elements.desc_crc,
		is_function,
		bb_name);
	send_and_clear(request);




	return D_OK;
}




/*
* Fucking ugly function resolves some of the operands to symbols name
* (text form)
*/

int	DDiffSqlExport::decorate_instr_line(ulong32 instr_rva, char *instr_string, DAnalyze *DA)
{

	int			ilen;
	char		itext_copy[255];
	_sinfo		*symbol;
	type_flags	*flags	=	DA->BinData.flags;

	_dinstr		*di	=	DA->get_dinstr_from_rva(instr_rva);


	// if this is a JUMP, JCC, CALL rel
	// put the destination in a fancy form
	if (di->linked_instr_rva)
	{

		// check if it has a name
		symbol = DA->Symbols->get_symbol_info(di->linked_instr_rva);
		if (symbol)
		{
			//DA->orva2va(di->linked_instr_rva)
			_snprintf(instr_string, 255-1, "%s{0x%08x - %s}",
				instr_string,
				(di->linked_instr_rva),
				symbol->name);
		}
		else
		{
			_snprintf(instr_string, 255-1, "%s{0x%08x}",
				instr_string,
				(di->linked_instr_rva));
		}
	}




	if (!daIS_F_INSTR_SYMBOL_IN_MEMIMM(flags[instr_rva]) &&
		!daIS_F_INSTR_SYMBOL_IN_IMM(flags[instr_rva]))
		return 0;

	//ilen	=	strlen(instr_string);
	strncpy((char*)&itext_copy, (char*)instr_string, sizeof(itext_copy)-1);


	if (daIS_F_INSTR_SYMBOL_IN_MEMIMM(flags[instr_rva]))
	{
		symbol = DA->Symbols->get_symbol_info(di->objMEMIMM_rva);
		if (symbol && (symbol->name[0] != 0))
		{
			// we have a symbol in mem imm, so in [] add 
			// a symbol name
			// travel till we find the ']' -> should be always available when
			// we have a memimm
			char	*op_end	=	strchr((char*)instr_string, ']');
			if (op_end)
			{
				int op_loc	=	(ulong32)op_end - (ulong32)instr_string;
				memcpy((char*)&itext_copy, (char*)instr_string, op_loc-1);
				itext_copy[op_loc-1] = 0;
				_snprintf((char*)&itext_copy, sizeof(itext_copy)-1, "%s{%s}%s",
					itext_copy,
					symbol->name,
					(char*)&instr_string[op_loc]);

			}
		}
	}

	if (daIS_F_INSTR_SYMBOL_IN_IMM(flags[instr_rva]))
	{
		symbol = DA->Symbols->get_symbol_info(di->objIMM_rva);
		if (symbol && (symbol->name[0] != 0))
		{
			_snprintf((char*)&itext_copy, sizeof(itext_copy)-1, "%s{%s}",
				itext_copy,
				symbol->name);
		}
	}

	strcpy(instr_string, (char*)&itext_copy);

	return D_OK;
}


/*
* If modified instruction uses objects we are trying to locate it.
*/

int	DDiffSqlExport::get_instr_objs(ulong32 instr_rva, DAnalyze *DA)
{

	type_ObjMatch::iterator	it;
	type_flags iflags = DA->BinData.flags[instr_rva];
	_dinstr *di = DA->get_dinstr_from_rva(instr_rva);

	if (daIS_F_INSTR_RELOCABLE_DATA_IN_MEMIMM(iflags))
	{
		if (!daIS_F_INSTR_USES_IMPORTED_API(iflags))
		{
			it = this->MapObjMatch.find(di->objMEMIMM_rva);
			if (it == this->MapObjMatch.end())
			{
				ulong32 temp = this->Diff->match_object(di->objMEMIMM_rva);

				// add this one to map
				this->MapObjMatch.insert(make_pair<ulong32, ulong32>(di->objMEMIMM_rva,temp));

			}
		}
	}


	if (daIS_F_INSTR_RELOCABLE_DATA_IN_IMM(iflags))
	{
		it = this->MapObjMatch.find(di->objIMM_rva);
		if (it == this->MapObjMatch.end())
		{
			ulong32 temp = this->Diff->match_object(di->objIMM_rva);
			this->MapObjMatch.insert(make_pair<ulong32, ulong32>(di->objIMM_rva,temp));
		}

	}


	return D_OK;
}


/*
* Function exports matched and unmatched objs. 
* this is only done for the patched module. 
*/
int	DDiffSqlExport::export_objs(void)
{
	_sinfo		*symbol;
	char		*s_name;
	type_ObjMatch::iterator	it;

	for (it = this->MapObjMatch.begin(); it != this->MapObjMatch.end(); it++)
	{
		ulong32 obj_rva = it->first;
		ulong32 obj_matched_rva = it->second;

#if DA_DEBUG_IT == 1
		flog("%s: OBJ: %08x -> %08x\n", __FUNCTION__, obj_rva, obj_matched_rva);
#endif

		s_name	=	NULL;
		symbol	=	this->DA1->Symbols->get_symbol_info(obj_rva);
		if (symbol)
		{
			s_name	=	(char*)&symbol->name;
		}


		_snprintf(request, sizeof(request)-1, SQL_DB_SQL_INSERT_TOBJECT,
			this->m1_id,
			obj_rva,
			obj_matched_rva,
			s_name);
		this->Sql.sp_sql_send(request);

	}


	this->MapObjMatch.clear();
	return D_OK;
}


#endif