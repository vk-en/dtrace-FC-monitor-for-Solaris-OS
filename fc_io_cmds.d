#!/usr/sbin/dtrace -qs
/*
 *  fibre chanel scan 
 *  Author: Vitaliy Kuznetsov @vk_en vitaliy@codingart.pw 
 */
/**********************************************************************************************************************************************/
/*
 *  args[] = 
 *  fct_cmd_t,cmd,
 *  fct_i_local_port_t,iport,
 *  scsi_task_t, task,

 *  fct_i_remote_port_t,irp);
 */

/*условие
* /((scsi_task_t *) args[2]->task_lu->lu_provider_private)->sl_name == "/dev/zvol/rdsk/tank3/zvol1" /
*/
    

/*READ*/
fc:::scsi-command
/(  ((scsi_task_t *) arg2)->task_cdb[0] == 40 /*scsi_cmd[0x28] = "read(10)"*/
 || ((scsi_task_t *) arg2)->task_cdb[0] == 136)/*scsi_cmd[0x88] = "read(16)"*/ 
 && ((scsi_task_t *) arg2)->task_flags & 0x40/
{
	/*arg*/
	this->cmd = arg0;
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
	

        @rcmds[stringof(this->krol->port_pwwn_str),stringof(this->zrport->rp_pwwn_str), stringof(this->sl->sl_name),
	     this->task->task_cdb[0], this->task->task_cdb[1]] = count();
}


/*WRITE*/
fc:::scsi-command
/(  ((scsi_task_t *) arg2)->task_cdb[0] == 42 /*scsi_cmd[0x2A] = "write(10)"*/
 || ((scsi_task_t *) arg2)->task_cdb[0] == 138)/*scsi_cmd[0x8A] = "write(16)"*/
 && ((scsi_task_t *) arg2)->task_flags & 0x20/
{
	/*arg*/
	this->cmd = arg0;
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
	
        @wcmds[stringof(this->krol->port_pwwn_str),stringof(this->zrport->rp_pwwn_str), stringof(this->sl->sl_name),
	     this->task->task_cdb[0], this->task->task_cdb[1]] = count();
}
/**********************************************************************************************************************************************/
profile:::tick-1s
{       
	printa("R|%s|%s|%s|0x%x|0x%x|%@10d|\n", @rcmds);
	printa("W|%s|%s|%s|0x%x|0x%x|%@10d|\n", @wcmds);
	trunc(@rcmds, 0);
	trunc(@wcmds, 0);
}


