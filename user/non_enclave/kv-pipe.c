/*
 *  Copyright (C) 2015, OpenSGX team, Georgia Tech & KAIST, All Rights Reserved
 *
 *  This file is part of OpenSGX (https://github.com/sslab-gatech/opensgx).
 *
 *  OpenSGX is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  OpenSGX is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSGX.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "iLSM.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/nvme_ioctl.h>
#include <stdlib.h>
#include <stdint.h>

#define RB_MODE_RD 0
#define RB_MODE_WR 1
#define ROUND 70
#define VALUE_SIZE 64
#define DIGEST_SIZE 64

char TMP_DIRECTORY_CONF[] = "/tmp/ipc_conf";
char TMP_DIRECTORY_RUN[] = "/tmp/ipc_run";
char TMP_FILE_NUMBER_FMT[] =  "/pipe_";
int NAME_BUF_SIZE = 256;
char Hex_value[] = "0123456789ABCDEF";

const unsigned int PAGE_SIZE = 4096;
const unsigned int MAX_BUFLEN = 1048576; // 1MB
const unsigned int NSID = 1;


int nvme_passthru(uint8_t opcode, uint8_t flags, uint16_t rsvd, uint32_t nsid,
        uint32_t cdw2, uint32_t cdw3, uint32_t cdw10, uint32_t cdw11,
        uint32_t cdw12, uint32_t cdw13, uint32_t cdw14, uint32_t cdw15,
        uint32_t data_len, void* data, uint32_t* result)
{
    struct nvme_passthru_cmd cmd = {
        .opcode         = opcode,
        .flags          = flags,
        .rsvd1          = rsvd,
        .nsid           = nsid,
        .cdw2           = cdw2,
        .cdw3           = cdw3,
        .metadata       = (uint32_t)(uintptr_t) NULL,
        .addr           = (uint64_t)(uintptr_t) data,
        .metadata_len   = 0,
        .data_len       = data_len,
        .cdw10          = cdw10,
        .cdw11          = cdw11,
        .cdw12          = cdw12,
        .cdw13          = cdw13,
        .cdw14          = cdw14,
        .cdw15          = cdw15,
        .timeout_ms     = 0,
        .result         = 0,
    };

    int err;

    err = ioctl(fd__, NVME_IOCTL_IO_CMD, &cmd);
    printf("err: %d, cmd.result: %d\n", err, cmd.result);
    if( !err ) *result = cmd.result;
    return err;
}
int Open(const char* dev)
{
    int err;
    
    err = open(dev, O_RDONLY);
    if( err < 0){
        puts("Fail opening device");
        return -1;
    }
    fd__ = err;

    struct stat nvme_stat;
    err = fstat(fd__, &nvme_stat);
    if( err < 0) return -1;
    if( !S_ISCHR(nvme_stat.st_mode) && !S_ISBLK(nvme_stat.st_mode)) return -1;

    return 0;
}
int Put(const char* key, const char* value, const int value_size)
{
    void* data = NULL;
    unsigned int nlb = (value_size-1)/PAGE_SIZE;
    unsigned int data_len = (nlb+1) * PAGE_SIZE;

    if( posix_memalign(&data, PAGE_SIZE, data_len))
        return -ENOMEM;

    memcpy(data, value, value_size);
    
    int err;
    uint32_t result;
    uint32_t cdw2, cdw3, cdw10, cdw11, cdw12, cdw13, cdw14, cdw15;
    cdw2 = cdw3 = cdw10 = cdw11 = cdw12 = cdw13 = cdw14 = cdw15 = 0;

    memcpy(&cdw10, key, 4);
    cdw12 = 0 | (0xFFFF & nlb);
    cdw13 = value_size;
    
    err = nvme_passthru(NVME_CMD_KV_PUT, 0, 0, NSID, cdw2, cdw3,
            cdw10, cdw11, cdw12, cdw13, cdw14, cdw15,
            data_len, data, &result);

    if( err < 0){
        puts("Fail nvme_passthru");
        return -1;
    }
    if( result != 0) return -1;

    return 0;
}
int Get(const char* key, char* value, int* value_size)
{
    void* data = NULL;
    unsigned int data_len = MAX_BUFLEN;
    unsigned int nlb = (MAX_BUFLEN-1) / PAGE_SIZE;

    if( posix_memalign(&data, PAGE_SIZE, data_len))
        return -ENOMEM;

    memset(data, 0, data_len);
    
    int err;
    uint32_t result;
    uint32_t cdw2, cdw3, cdw10, cdw11, cdw12, cdw13, cdw14, cdw15;
    cdw2 = cdw3 = cdw10 = cdw11 = cdw12 = cdw13 = cdw14 = cdw15 = 0;

    memcpy(&cdw10, key, 4);
    cdw12 = 0 | (0xFFFF & nlb);
    
    err = nvme_passthru(NVME_CMD_KV_GET, 0, 0, NSID, cdw2, cdw3,
            cdw10, cdw11, cdw12, cdw13, cdw14, cdw15,
            data_len, data, &result);
    
    if( err < 0){
        puts("Fail IOCTL");
        return -1;
    }
    
    if( err == 0x7C1){
        puts("No such key");
        return -2;
    }
    if( result > 0){ // Key exists
        *value_size = (int)result;
        memcpy(value, (char*)data, (int)result);
    }
    else{
        puts("Never reach here");
        value = NULL;
        *value_size = 0;
    }
    return result;
}
static int pipe_init(int flag_dir)
{
	int ret;

	if(flag_dir == 0)
		ret = mkdir(TMP_DIRECTORY_CONF, 0770);
	else if(flag_dir == 1)
		ret = mkdir(TMP_DIRECTORY_RUN, 0770);

	if(ret == -1)
	{
		if(errno != EEXIST) {
            puts("Fail to mkdir");
            return -1;
        }
	}
	return 0;
}

static int pipe_open(char *unique_id, int is_write, int flag_dir)
{
	char name_buf[NAME_BUF_SIZE];

    if (flag_dir == 0) {
        strcpy(name_buf, TMP_DIRECTORY_CONF);
        strcpy(name_buf+strlen(name_buf), TMP_FILE_NUMBER_FMT);
        strcpy(name_buf+strlen(name_buf), unique_id);
    }
    else if (flag_dir == 1) {
        strcpy(name_buf, TMP_DIRECTORY_RUN);
        strcpy(name_buf+strlen(name_buf), TMP_FILE_NUMBER_FMT);
        strcpy(name_buf+strlen(name_buf), unique_id);
    }

	int ret = mknod(name_buf, S_IFIFO | 0770, 0);
	if(ret == -1)
	{
        if(errno != EEXIST) {
            puts("Fail to mknod");
            return -1;
        }
	}

	int flag = O_ASYNC;
	if(is_write)
		flag |= O_WRONLY;
	else
		flag |= O_RDONLY;

	int fd = open(name_buf, flag);

    if(fd == -1)
    {
        puts("Fail to open");
        return -1;
    }

    return fd;
}
void send_ae(int fd_ae, char* buf)
{
    int _complete_len = strlen(buf);
    write(fd_ae, &_complete_len, sizeof(int));
    write(fd_ae, buf, _complete_len+1);
}
int receive_ea(int fd_ea, char* buf)
{
    int _kv_command_len;
    read(fd_ea, &_kv_command_len, sizeof(int));
    read(fd_ea, buf, _kv_command_len+1);
    return _kv_command_len;
}

int main(int argc, char *argv[]) {
    int fd_ea = -1;
    int fd_ae = -1;

    char port_enc_to_app[NAME_BUF_SIZE];
    char port_app_to_enc[NAME_BUF_SIZE];

    if(argc != 3){
        printf("Usage: ./simple-pipe [PORT_ENCLAVE_TO_APP] [PORT_APP_TO_ENCLAVE]\n");
        exit(1);
    }
    
    strcpy(port_enc_to_app, argv[1]);
    strcpy(port_app_to_enc, argv[2]);

    if(pipe_init(0) < 0) {
        perror("Error in pipe_init");
        exit(1);
    }

    if((fd_ea = pipe_open(port_enc_to_app, RB_MODE_RD, 0)) < 0) {
        perror("Error in pipe_open");
        exit(1);
    }

    if((fd_ae = pipe_open(port_app_to_enc, RB_MODE_WR, 0)) < 0) {
        perror("Error in pipe_open");
        exit(1);
    }
    
    // Receive KV from Enclave
    char kv_command[20];
    int kv_command_len;
    unsigned char key[5];
    unsigned char value[VALUE_SIZE + 1];
    unsigned char hmac[DIGEST_SIZE + 1];

    for( int i=0 ; i<ROUND ; i++){
        kv_command_len = receive_ea(fd_ea, kv_command);       
        if( !strncmp(kv_command, "PUT", kv_command_len)){
            read(fd_ea, key, 4);
            key[4] = '\0';

            read(fd_ea, value, VALUE_SIZE);
            value[VALUE_SIZE] = '\0';
         
            read(fd_ea, hmac, DIGEST_SIZE);
            hmac[DIGEST_SIZE] = '\0';

            printf("Key = %s\n", key);
            printf("Value = %s\nHMAC = ", value);
            for( int i=0 ; i<DIGEST_SIZE ; i++)
                printf("%c", hmac[i]);
            printf("\n");
            
            //Put( &key, &value, VALUE_SIZE);
        }
        else if( !strncmp(kv_command, "GET", kv_command_len)){
            //Get(&key, &value_buf, &value_buf_size);
        }
        send_ae(fd_ae, "COMPLETE");
    }
    printf("End loop?\n");
    int err = Open("/dev/nvme0n1");

    /*
    char value_buf[VALUE_SIZE+1];
    int* value_buf_size;
    */

    /*
    for( int i=0 ; i <ROUND ; i++){
        //Get(&key, &value_buf, &value_buf_size);
        //printf("%s\n", value_buf);

        //"Send Put and Get Completion signal to Enclave"
        
        int do_something_len = strlen("Do_Something");
        write(fd_ae, &do_something_len, sizeof(int));
        write(fd_ae, "Do_Something", do_something_len+1);

        write(fd_ae, value_buf, VALUE_SIZE);

        read(fd_ea, value, VALUE_SIZE);
        printf("Returned Value = %s\n", value);
        
    }*/

    // Send complete signal
    
    send_ae(fd_ae, "COMPLETE");

    //int complete_len = strlen("Complete");
    //write(fd_ae, &complete_len, sizeof(int));
    //write(fd_ae, "Complete", complete_len+1);

    return 0;

}
