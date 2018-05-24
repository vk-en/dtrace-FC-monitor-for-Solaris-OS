#!/usr/sbin/dtrace -s
/*
 *  fibre chanel scan v.1.0 
 *  Author: Vitaliy Kuznetsov @vk_en vitaliy@codingart.pw . 
 */

#pragma D option quiet
#pragma D option defaultargs

inline int SCREEN = 21;
string scsi_cmd[unsigned int];
 
dtrace:::BEGIN
{	
   	lines = SCREEN +1;
   	secs = $1 ? $1 : 3;
   	interval = secs;
   	counts = $2 ? $2 : -1; 
   	readiops = readbytes = 0;
   	writeiops = writebytes = 0;
   	wmaxlatency = rmaxlatency = 0; 
   	wminlatency = rminlatency = 999999999;
   	first = 1;
   	zeros =0;
        scsi_cmd[0x00] = "test_unit_ready";
        scsi_cmd[0x01] = "rezero/rewind";
        scsi_cmd[0x03] = "request_sense";
        scsi_cmd[0x04] = "format";
        scsi_cmd[0x05] = "read_block_limits";
        scsi_cmd[0x07] = "reassign";
        scsi_cmd[0x08] = "read";
        scsi_cmd[0x0a] = "write";
        scsi_cmd[0x0b] = "seek";
        scsi_cmd[0x0f] = "read_reverse";
        scsi_cmd[0x10] = "write_file_mark";
        scsi_cmd[0x11] = "space";
        scsi_cmd[0x12] = "inquiry";
        scsi_cmd[0x13] = "verify";
        scsi_cmd[0x14] = "recover_buffer_data";
        scsi_cmd[0x15] = "mode_select";
        scsi_cmd[0x16] = "reserve";
        scsi_cmd[0x17] = "release";
        scsi_cmd[0x18] = "copy";
        scsi_cmd[0x19] = "erase_tape";
        scsi_cmd[0x1a] = "mode_sense";
        scsi_cmd[0x1b] = "load/start/stop";
        scsi_cmd[0x1c] = "get_diagnostic_results";
        scsi_cmd[0x1d] = "send_diagnostic_command";
        scsi_cmd[0x1e] = "door_lock";
        scsi_cmd[0x23] = "read_format_capacity";
        scsi_cmd[0x25] = "read_capacity";
        scsi_cmd[0x28] = "read(10)";
        scsi_cmd[0x2a] = "write(10)";
        scsi_cmd[0x2b] = "seek(10)";
        scsi_cmd[0x2e] = "write_verify";
        scsi_cmd[0x2f] = "verify(10)";
        scsi_cmd[0x30] = "search_data_high";
        scsi_cmd[0x31] = "search_data_equal";
        scsi_cmd[0x32] = "search_data_low";
        scsi_cmd[0x33] = "set_limits";
        scsi_cmd[0x34] = "read_position";
        scsi_cmd[0x35] = "synchronize_cache";
        scsi_cmd[0x37] = "read_defect_data";
        scsi_cmd[0x39] = "compare";
        scsi_cmd[0x3a] = "copy_verify";
        scsi_cmd[0x3b] = "write_buffer";
        scsi_cmd[0x3c] = "read_buffer";
        scsi_cmd[0x3e] = "read_long";
        scsi_cmd[0x3f] = "write_long";
        scsi_cmd[0x44] = "report_densities/read_header";
        scsi_cmd[0x4c] = "log_select";
        scsi_cmd[0x4d] = "log_sense";
        scsi_cmd[0x55] = "mode_select(10)";
        scsi_cmd[0x56] = "reserve(10)";
        scsi_cmd[0x57] = "release(10)";
        scsi_cmd[0x5a] = "mode_sense(10)";
        scsi_cmd[0x5e] = "persistent_reserve_in";
        scsi_cmd[0x5f] = "persistent_reserve_out";
        scsi_cmd[0x80] = "write_file_mark(16)";
        scsi_cmd[0x81] = "read_reverse(16)";
        scsi_cmd[0x83] = "extended_copy";
        scsi_cmd[0x88] = "read(16)";
        scsi_cmd[0x8a] = "write(16)";
        scsi_cmd[0x8c] = "read_attribute";
        scsi_cmd[0x8d] = "write_attribute";
        scsi_cmd[0x8f] = "verify(16)";
        scsi_cmd[0x91] = "space(16)";
        scsi_cmd[0x92] = "locate(16)";
        scsi_cmd[0x9e] = "service_action_in(16)";
        scsi_cmd[0x9f] = "service_action_out(16)";
        scsi_cmd[0xa0] = "report_luns";
        scsi_cmd[0xa2] = "security_protocol_in";
        scsi_cmd[0xa3] = "maintenance_in";
        scsi_cmd[0xa4] = "maintenance_out";
        scsi_cmd[0xa8] = "read(12)";
        scsi_cmd[0xa9] = "service_action_out(12)";
        scsi_cmd[0xaa] = "write(12)";
        scsi_cmd[0xab] = "service_action_in(12)";
        scsi_cmd[0xac] = "get_performance";
        scsi_cmd[0xAF] = "verify(12)";
        scsi_cmd[0xb5] = "security_protocol_out";	
}

profile:::tick-1sec
{
   secs--;
}

/*
Argument Types for fc:fct:fct_xfer_scsi_data:xfer-start:
   args[0]: conninfo_t *       ->  this->cmdz
   args[1]: fc_port_info_t *   ->  this->ilport  (local port (fc)) (fct_i_local_port_t *)
   args[2]: scsicmd_t *        ->  this->task    (scsi_task_t *)
   args[3]: fc_port_info_t *   ->  this->rport   (remote port (fc target)) (fct_i_remote_port_t *)
*/

/*READ*/
fc:::xfer-start
/(  ((scsi_task_t *) arg2)->task_cdb[0] == 40 /*scsi_cmd[0x28] = "read(10)"*/
 || ((scsi_task_t *) arg2)->task_cdb[0] == 136)/*scsi_cmd[0x88] = "read(16)"*/ 
 && (((scsi_task_t *) arg2)->task_flags & 0x40)
 && stringof(((fct_local_port_t *) ((fct_i_local_port_t *) arg1)->iport_port )->port_pwwn_str) == "21000024ff41e4d9"/  /*    <----------------- Enter FC wwn   */ 
{
	/*arg*/
	this->cmdz = arg0;
	this->ilport = (fct_i_local_port_t *) arg1;
	this->task = (scsi_task_t *) arg2;
	this->rport = arg3;
        /*wwn fc*/
        this->krol = (fct_local_port_t *) this->ilport->iport_port;
	/*fct - get fibre canel target wwn*/
   	this->irport= (fct_i_remote_port_t *) this->rport;
   	this->zrport= (fct_remote_port_t *) this->irport->irp_rp;
	/*lun*/
	this->task_lu = (stmf_lu_t *) this->task->task_lu; 
	this->sl = (sbd_lu_t *) this->task_lu->lu_provider_private;
	/*Read MB*/
	readbytes = readbytes + this->task->task_cmd_xfer_length;
	/*Info*/
        @rcmds[stringof(this->krol->port_pwwn_str),stringof(this->zrport->rp_pwwn_str), stringof(this->sl->sl_name),
	     this->task->task_cdb[0], this->task->task_cdb[1]] = count();
	/*IOPS*/
	++readiops;
}

/*WRITE*/
fc:::xfer-start
/(  ((scsi_task_t *) arg2)->task_cdb[0] == 42 /*scsi_cmd[0x28] = "write(10)"*/
 || ((scsi_task_t *) arg2)->task_cdb[0] == 138)/*scsi_cmd[0x88] = "write(16)"*/ 
 && (((scsi_task_t *) arg2)->task_flags & 0x20)
 && stringof(((fct_local_port_t *) ((fct_i_local_port_t *) arg1)->iport_port )->port_pwwn_str) == "21000024ff41e4d9"/   /*    <----------------- Enter FC  wwn  */ 
{
	/*arg*/
	this->cmdz = arg0;
	this->ilport = (fct_i_local_port_t *) arg1;
	this->task = (scsi_task_t *) arg2;
	this->rport = arg3;
        /*wwn fc*/
        this->krol = (fct_local_port_t *) this->ilport->iport_port;
	/*fct - get fibre canel target wwn*/
   	this->irport= (fct_i_remote_port_t *) this->rport;
   	this->zrport= (fct_remote_port_t *) this->irport->irp_rp;
	/*lun*/
	this->task_lu = (stmf_lu_t *) this->task->task_lu; 
	this->sl = (sbd_lu_t *) this->task_lu->lu_provider_private;
	/*Write MB*/
	writebytes = writebytes + this->task->task_cmd_xfer_length;
	
	/*Info*/
        @wcmds[stringof(this->krol->port_pwwn_str),stringof(this->zrport->rp_pwwn_str), stringof(this->sl->sl_name),
	     this->task->task_cdb[0], this->task->task_cdb[1]] = count();
    	/*IOPS*/
	++writeiops;
}

profile:::tick-1sec
/counts == 0/
{
   exit(0);
}

profile:::tick-1sec
/secs == 0/
{
	rmbps = readbytes / (1024 * 1024 * interval);
   	wmbps = writebytes / (1024 * 1024 * interval);
        printf("O|IOPS|Speed MB/s\n");
	/*printa("R|%s|%s|%s|0x%x|0x%x|%@10d|\n", @rcmds); *//*Print detailed information on reading*/
	printf("R|%4d|%4d\n",readiops/interval, rmbps);
	/*printa("W|%s|%s|%s|0x%x|0x%x|%@10d|\n", @wcmds); *//*Print detailed information on writing*/
	printf("W|%4d|%4d\n",writeiops/interval, wmbps);

	readiops = readbytes = 0;
   	writeiops = writebytes = rmaxlatency = wmaxlatency = 0;
   	wminlatency = rminlatency = 999999999;
	/*clear statistics*/
	trunc(@rcmds);
	trunc(@wcmds);
	/*trunc(@wiops);
	trunc(@riops);*/
	/*exit(0);*//*Capture data once*/
	secs = interval;
}
