#include "test.h"
//#include "mdh_sha512_hmac.h"
#include "../include/polarssl/sha512.h"
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>
#include <sgx-lib.h>
#include <string.h>

#define RB_MODE_RD 0
#define RB_MODE_WR 1
#define ROUND 70
#define VALUE_SIZE 64
#define DIGEST_SIZE 64

// MemTable-related
#define MAX_SKIPLIST_NODE 4096
#define MAX_SKIPLIST_LEVEL 10
#define SKIPLIST_NIL 0

// SSTable-related
#define MAX_SSTABLE_LIST 200
#define MAX_BMF_CACHE_ENTRY 10
#define MAX_SSTABLE_LEVEL0 4
#define MAX_SSTABLE_LEVEL1 16
#define MAX_SSTABLE_LEVEL2 128
#define MAX_SSTABLE_LEVEL3 65537

// MerkleTree-related
#define MAX_SKIPLIST_MT_INTERMIDIATE 2048
#define MAX_SSTABLE_MT_INTERMIDIATE 4096

const unsigned int MAX_SSTABLE_LEVEL[4] = {
    MAX_SSTABLE_LEVEL0,
    MAX_SSTABLE_LEVEL1,
    MAX_SSTABLE_LEVEL2,
    MAX_SSTABLE_LEVEL3
};
const unsigned int COMPACTION_THRESHOLD_LEVEL[4]={
    MAX_SSTABLE_LEVEL0-1,
    MAX_SSTABLE_LEVEL1-1,
    MAX_SSTABLE_LEVEL2-1,
    MAX_SSTABLE_LEVEL3-1
};

char TMP_DIRECTORY_CONF[] = "/tmp/ipc_conf";
char TMP_DIRECTORY_RUN[] = "/tmp/ipc_run";
char TMP_FILE_NUMBER_FMT[] =  "/pipe_";
int NAME_BUF_SIZE = 256;
char HEX_char[] = "0123456789ABCDEF";
char hex_char[] = "0123456789abcdef";

// MemTable-related
typedef struct _SKIPLIST_NODE{
    char key[5];
    char hmac[DIGEST_SIZE];
    struct _SKIPLIST_NODE* next;
}SKIPLIST_NODE;

typedef struct _SKIPLIST_HEAD{
    unsigned int count;
    SKIPLIST_NODE* forward;
    SKIPLIST_NODE* backward;
}SKIPLIST_HEAD;

// SSTable-related
typedef struct _SUPER_LEVEL_INFO{
    unsigned int level_count[4];
}SUPER_LEVEL_INFO;

typedef struct _SUPER_SSTABLE_LIST{
    unsigned int head;
    unsigned int tail;
}SUPER_SSTABLE_LIST;

typedef struct _SSTABLE_NODE{
    char key[5];
    char hmac[DIGEST_SIZE];
}SSTABLE_NODE;

typedef struct _SUPER_SSTABLE_INFO{
    unsigned int level;
    unsigned int total_entry;
    //SSTABLE_NODE* forward;
}SUPER_SSTABLE_INFO;

// MerkleTree-related
typedef struct _MerkleTree{
    unsigned char hmac[DIGEST_SIZE];
}MerkleTree;


// Global-variable
SKIPLIST_HEAD* skiphead;

SUPER_LEVEL_INFO* super_level_info;
SUPER_SSTABLE_LIST* super_sstable_list;
SUPER_SSTABLE_INFO* super_sstable_list_level[4];

void MemTable_Init()
{
    if( skiphead == NULL)
        skiphead = (SKIPLIST_HEAD*)malloc(sizeof(SKIPLIST_HEAD));
    skiphead->count = 0;
    skiphead->forward = NULL;
    skiphead->backward = NULL;
}

void SSTable_Init()
{
    // SUPER_LEVEL_INFO*
    if( super_level_info == NULL)
        super_level_info = (SUPER_LEVEL_INFO*)malloc(sizeof(SUPER_LEVEL_INFO));
    for( int i=0 ; i<4 ; i++)
        super_level_info->level_count[i] = 0;

    // SUPER_SSTABLE_LIST*
    if( super_sstable_list == NULL)
        super_sstable_list = (SUPER_SSTABLE_LIST*)malloc(sizeof(SUPER_SSTABLE_LIST)*4);
    for( int i=0 ; i<4 ; i++){
        super_sstable_list[i].head = 0;
        super_sstable_list[i].tail = 0;
    }
    // SUOER_SSTABLE_INFO*
    for( int i=0 ; i<4 ; i++){
        if( super_sstable_list_level[i] == NULL)
            super_sstable_list_level[i] = (SUPER_SSTABLE_INFO*)malloc(sizeof(SUPER_SSTABLE_INFO)*MAX_SSTABLE_LEVEL[i]);
        for( int j=0 ; j<MAX_SSTABLE_LEVEL[i] ; j++){
            super_sstable_list_level[i][j].level = -1;
            super_sstable_list_level[i][j].total_entry = 0;
            //super_sstable_list_level[i][j].forward = NULL;
        }
    }
}
void MemTable_Remove()
{
    SKIPLIST_NODE* cur = skiphead->forward;
    SKIPLIST_NODE* trash = cur;
    while(cur){
        cur = cur->next;
        free(trash);
        trash = cur;
    }
    skiphead->count = 0;
    skiphead->forward = NULL;
    skiphead->backward = NULL;

}
void MemTable_Fin()
{
    MemTable_Remove();
    if(skiphead != NULL)
        free(skiphead);
}
void SSTable_Partial_Remove(int level, int offset)
{
    //printf("SSTable_Partial_Remove START...");
    char filename[30];
    sprintf(filename, "sstable/%d_%d.txt", level, offset);
    int nResult = remove(filename);
    if( nResult == -1){
        printf("SSTable Removal Error!\n");
        return;
    }
    super_sstable_list_level[level][offset].total_entry = 0;
    super_sstable_list_level[level][offset].level = -1;
    //super_sstable_list_level[level][offset].forward = NULL;

    super_sstable_list[level].head = (super_sstable_list[level].head + 1) % MAX_SSTABLE_LEVEL[level];

    super_level_info->level_count[level]--;
}
/*
void SSTable_All_Remove()
{
    SSTABLE_NODE* temp;
    for( int i=0 ; i<4 ; i++){
        for( int j=super_sstable_list[i].head ; j!= super_sstable_list[i].tail ; j = (j+1)%MAX_SSTABLE_LEVEL[i]){
            temp = super_sstable_list_level[i][j].forward;
            if( temp != NULL)
                free(temp);
            super_sstable_list_level[i][j].total_entry = 0;
            super_sstable_list_level[i][j].level = -1;
            super_sstable_list_level[i][j].forward = NULL;
            //super_sstable_list_level[i][j].root_hash[0] = '\0';
        }
        super_sstable_list[i].head = 0;
        super_sstable_list[i].tail = 0;

        super_level_info->level_count[i] = 1;
    }
}*/
void SSTable_Fin()
{
    //SSTable_All_Remove();
    for( int i=0 ; i<4 ; i++)
        if( super_sstable_list_level[i] != NULL) free(super_sstable_list_level[i]);

    if( super_sstable_list != NULL)
        free(super_sstable_list);
    if( super_level_info != NULL)
        free(super_level_info);
}
void MerkleTree_Construct(int level, int offset)
{   
    //SSTABLE_NODE* trail;
    MerkleTree MT[MAX_SKIPLIST_MT_INTERMIDIATE];
    unsigned char _tmp_buf1[DIGEST_SIZE*2 + 1]={'\0',};
    unsigned char _tmp_buf2[DIGEST_SIZE + 1]={'\0',};
    unsigned char _tmp_hmac_buf[DIGEST_SIZE+1]={'\0',};
    char key1[5];
    char key2[5];
    int idx_MT, odd=0;
    int num_of_MT = 0;

    //trail = super_sstable_list_level[level][offset].forward;
    char filename[30];
    sprintf(filename, "sstable/%d_%d.txt", 0, offset);
    FILE* fp = fopen(filename, "at+"); // read and append

    do{
        idx_MT = 0;
        if(num_of_MT == 0){ // copy From sstable To _tmp_buf
            if( super_sstable_list_level[level][offset].total_entry%2 == 0){ // for even case
                odd = 1;
            }
            else odd = 0;
            for( int i=0 ; i<super_sstable_list_level[level][offset].total_entry-odd ; i+=2){
                fscanf(fp, "%s", key1);
                //for( int j=0 ; j<4 ; j++) printf("%c", key1[j]);
                //printf("\n");
                fscanf(fp, "%s", _tmp_buf1);
                //for( int k=0 ; k<DIGEST_SIZE ; k++) printf("%c",_tmp_buf1[k + DIGEST_SIZE * idx_MT]);
                //printf("\n");
                fscanf(fp, "%s", key2);
                //for( int j=0 ; j<4 ; j++) printf("%c", key2[j]);
                //printf("\n");
                fscanf(fp, "%s", _tmp_buf2);
                //for( int k=0 ; k<DIGEST_SIZE ; k++) printf("%c",_tmp_buf2[k + DIGEST_SIZE * idx_MT]);
                //printf("\n");
                idx_MT++;
                strcat(_tmp_buf1, _tmp_buf2);
                sha512(_tmp_buf1, DIGEST_SIZE*2 , _tmp_hmac_buf, 0);
                //printf("H");
                memcpy(&MT[num_of_MT++].hmac, _tmp_buf1, DIGEST_SIZE);
                memset(_tmp_buf1, 0, sizeof(_tmp_buf1));
                memset(_tmp_buf2, 0, sizeof(_tmp_buf2));
            }
            if( odd ){ // 마지막 하나 처리
                fscanf(fp, "%s", key1);
                //for( int j=0 ; j<4 ; j++) printf("%c", key1[j]);
                //printf("\n");
                fgets(_tmp_buf1, DIGEST_SIZE+1, fp);
                //for( int k=0 ; k<DIGEST_SIZE ; k++) printf("%c",_tmp_buf1[k + DIGEST_SIZE * idx_MT]);
                //printf("\n");
                strcat(_tmp_buf1, _tmp_buf1);
                sha512(_tmp_buf1, DIGEST_SIZE*2 , _tmp_hmac_buf, 0);
                //printf("H");
                memcpy(&MT[num_of_MT++].hmac, _tmp_buf1, DIGEST_SIZE);
            }
        }
        else{ // copy From _tmp_buf To _tmp_buf 
            if( num_of_MT%2 == 0){ // for even case
                for( int i=0 ; i<num_of_MT ; i+=2){
                    sha512(MT[i].hmac, DIGEST_SIZE*2, _tmp_hmac_buf, 0);
                    memcpy(&MT[idx_MT++].hmac, _tmp_hmac_buf, DIGEST_SIZE);
                    //printf("H");
                }
            }
            else{ // for odd case 
                for( int i=0 ; i<num_of_MT+1 ; i+=2){
                    sha512(MT[i].hmac, DIGEST_SIZE*2 , _tmp_hmac_buf, 0);
                    memcpy(&MT[idx_MT++].hmac, _tmp_hmac_buf, DIGEST_SIZE);
                    //printf("H");
                }
            }
            num_of_MT = idx_MT;
        }
        //printf("    ...MerkleTree_end\n");
        if( num_of_MT == 1){
            fprintf(fp, "HMAC\n");
            for( int i=0 ; i<DIGEST_SIZE ; i++)
                fprintf(fp, "%d ",MT[idx_MT].hmac[i]);
            fprintf(fp, "\n");
            break;
        }
    }while(num_of_MT >= 2);
    fclose(fp);
}
void MemTable_Compaction()
{
    //printf("Compaction START\n");
    SKIPLIST_NODE* memtemp = skiphead->forward;
    //SSTABLE_NODE* ssttemp = (SSTABLE_NODE*)malloc(sizeof(SSTABLE_NODE) * skiphead->count);
    int idx_ssttemp=0;
    int num = skiphead->count;
    char filename[30];
    FILE* sfp;
    sprintf(filename, "sstable/%d_%d.txt", 0, super_sstable_list[0].tail);
    sfp = fopen(filename, "w");

    while(num--){
        for( int i=0 ; i<4 ; i++)
            fprintf(sfp, "%c", memtemp->key[i]);
        fprintf(sfp,"\n");
        for( int i=0 ; i<DIGEST_SIZE ; i++)
            fprintf(sfp, "%c", memtemp->hmac[i]);
        fprintf(sfp, "\n");
        idx_ssttemp++;
        memtemp = memtemp->next;
    }
    fclose(sfp);

    super_sstable_list_level[0][super_sstable_list[0].tail].level = 0;
    super_sstable_list_level[0][super_sstable_list[0].tail].total_entry = idx_ssttemp;
    //super_sstable_list_level[0][super_sstable_list[0].tail].forward = ssttemp;
    /* MerkleTree_Construct */
    MerkleTree_Construct(0, super_sstable_list[0].tail);
    
    super_sstable_list[0].tail = (super_sstable_list[0].tail + 1) % MAX_SSTABLE_LEVEL[0];

    //level count
    super_level_info->level_count[0]++;
    MemTable_Remove();
}
void SSTable_Compaction(unsigned int victim_level)
{
    //printf("SSTable Compaction START\n");
    unsigned int s1;
    unsigned int s2;
    int total_s1, total_s2;
    char key1[5];
    char key2[5];
    unsigned char _tmp_buf1[DIGEST_SIZE*2 + 1]={'\0',};
    unsigned char _tmp_buf2[DIGEST_SIZE + 1]={'\0',};
    unsigned char _tmp_hmac_buf[DIGEST_SIZE+1]={'\0',};

    //SSTABLE_NODE* sst_trail1, *sst_trail2;
    //SSTABLE_NODE* ssttemp;
    int new_level = victim_level + 1;
    int idx_ssttemp = 0;

    s1 = super_sstable_list[victim_level].head;
    s2 = (super_sstable_list[victim_level].head + 1) % MAX_SSTABLE_LEVEL[victim_level];

    total_s1 = super_sstable_list_level[victim_level][s1].total_entry;
    total_s2 = super_sstable_list_level[victim_level][s2].total_entry;
    //ssttemp = (SSTABLE_NODE*)malloc(sizeof(SSTABLE_NODE) * (total_s1 + total_s2));
    //sst_trail1 = super_sstable_list_level[victim_level][s1].forward;
    //sst_trail2 = super_sstable_list_level[victim_level][s2].forward;
    
    char filename[30];
    char* tok;
    FILE* sfp1, *sfp2;
    sprintf(filename, "sstable/%d_%d.txt", victim_level, s1);
    sfp1 = fopen(filename, "r");
    sprintf(filename, "sstable/%d_%d.txt", victim_level, s2);
    sfp2 = fopen(filename, "r");
    FILE* sfp3;
    sprintf(filename, "sstable/%d_%d.txt", new_level, super_sstable_list[new_level].tail);
    sfp3 = fopen(filename, "at+");
    // Non-duplicated sstable 1 Compaction 
    for( int i=0 ; i<total_s2 ; i++){
        fscanf(sfp2, "%s", key2);
        for( int k=0 ; k<4 ; k++) printf("%c", key2[k]);
        fscanf(sfp2, "%s", _tmp_buf2);
        for( int k=0 ; k<DIGEST_SIZE ; k++) printf("%c", _tmp_buf2[k]);

        for( int j=0 ; j<total_s1 ; j++){
            fscanf(sfp1, "%s", key1);
            fscanf(sfp1, "%s", _tmp_buf1);
            
            if( strncmp(key1, key2, 4) == 0) {
                break;
            }
            else{
                for( int k=0 ; k<4 ; k++) fprintf(sfp3, "%c", key1[k]);
                fprintf(sfp3, "\n");
                for( int k=0 ; k<DIGEST_SIZE ; k++) fprintf(sfp3, "%c", _tmp_buf1[k]);
                fprintf(sfp3, "\n");
            }
        }
        rewind(sfp1);
        //memcpy(ssttemp[idx_ssttemp].key, sst_trail1->key, 4);
        //ssttemp[idx_ssttemp].key[4] = '\0';
        //memcpy(ssttemp[idx_ssttemp].hmac, sst_trail1->hmac, DIGEST_SIZE);
        idx_ssttemp++;
    }
    printf("After first for-loop\n");
    // Remained sstable2 Compaction 
    rewind(sfp2);
    for( int i=0 ; i< total_s2 ; i++){
        fscanf(sfp2, "%s", key2);
        for( int k=0 ; k<4 ; k++) printf("%c", key2[k]);
        fscanf(sfp2, "%s", _tmp_buf2);
        for( int k=0 ; k<DIGEST_SIZE ; k++) printf("%c", _tmp_buf2[k]);

        for( int k=0 ; k<4 ; k++) fprintf(sfp3, "%c", key2[k]);
        fprintf(sfp3, "\n");
        for( int k=0 ; k<DIGEST_SIZE ; k++) fprintf(sfp3, "%c", _tmp_buf2[k]);
        fprintf(sfp3, "\n");
        //memcpy(ssttemp[idx_ssttemp].key, sst_trail2->key, 4);
        //ssttemp[idx_ssttemp].key[4] = '\0';
        //memcpy(ssttemp[idx_ssttemp].hmac, sst_trail2->hmac, DIGEST_SIZE);
        idx_ssttemp++;
    }
    printf("After second for-loop\n");
    fclose(sfp1);
    fclose(sfp2);
    fclose(sfp3);

    super_sstable_list_level[new_level][super_sstable_list[new_level].tail].level = new_level;
    super_sstable_list_level[new_level][super_sstable_list[new_level].tail].total_entry = idx_ssttemp;
    //super_sstable_list_level[new_level][super_sstable_list[new_level].tail].forward = ssttemp;
    printf("Merkle SST START\n");
    //MerkleTree_Construct(new_level, super_sstable_list[0].tail);
    printf("Merkle SST END\n");
    super_sstable_list[new_level].tail = (super_sstable_list[new_level].tail + 1) % MAX_SSTABLE_LEVEL[new_level];

    super_level_info->level_count[new_level]++;

    SSTable_Partial_Remove(victim_level, s1);
    SSTable_Partial_Remove(victim_level, s2);
    
    //printf("SSTable Compaction END\n");
}
int Is_MemTable_Full()
{
    //if( skiphead->count == MAX_SKIPLIST_NODE) return 1;
    if( skiphead->count == 5) return 1;
    else return 0;
}

int Is_SSTable_FULL(unsigned int* cnt)
{
    unsigned int victim_level = 0x7ff;
    for( int level = 2 ; level >= 0 ; level--){
        if( super_level_info->level_count[level] >=2 
                && super_level_info->level_count[level]>= COMPACTION_THRESHOLD_LEVEL[level]){
            victim_level = level;
            break;
        }
    }
    if( victim_level == 0x7ff) return 0;
    else{
        printf("Before do compaction\n");
        SSTable_Compaction(victim_level);
        printf("After do compaction\n");
        (*cnt)++;
        return 1;
    }
}
int MemTable_Search(unsigned char* org_key)
{
    SKIPLIST_NODE* trail = skiphead->forward;
    while(trail){
        if( strncmp(trail->key, org_key, 4) == 0) return 1;
        trail = trail->next;
    }
    return 0;
}
int MemTable_Insertion(unsigned char* org_key, unsigned char* org_hmac)
{
    SKIPLIST_NODE* temp;
    
    if( MemTable_Search(org_key) == 1) return 1;
    temp = (SKIPLIST_NODE*)malloc(sizeof(SKIPLIST_NODE));
    if( temp == NULL) return 0;
    temp->next = NULL;
    memcpy(temp->key, org_key, 4);
    temp->key[4] = '\0';
    org_hmac[DIGEST_SIZE] = '\0';
    memcpy(temp->hmac, org_hmac, DIGEST_SIZE);

    if( skiphead->forward == NULL){
        skiphead->backward = temp;
        skiphead->forward = temp;
    }
    else{
        skiphead->backward->next = temp;
        skiphead->backward = temp;
    }
    skiphead->count++;
    //printf("MemTable Insertion Worked Well\n");
    return 1;
}
void MemTable_Print()
{
    SKIPLIST_NODE* trail = skiphead->forward;
    while(trail){
        for( int i=0 ; i<4 ; i++)
            printf("%c",trail->key[i]);
        printf(" ");
        trail = trail->next;
    }
    printf(" ....NIL\n");
}
/*
void SSTable_Print()
{
    printf("SSTable Print START\n");
    SSTABLE_NODE* trail;

    for( int i=0 ; i<4 ; i++){
        printf("<Lv>: %d\n",i);
        for( int j=super_sstable_list[i].head ; j!= super_sstable_list[i].tail ; j = (j+1)%MAX_SSTABLE_LEVEL[i]){
            trail = super_sstable_list_level[i][j].forward;
            for( int k=0 ; k<super_sstable_list_level[i][j].total_entry ; k++){
                for( int p=0 ; p<4 ; p++)
                    printf("%c", trail[k].key[p]);
                printf(" ");
            }
            printf(" ....NIL_SS\n");
        }
    }
    printf("SSTable Print END\n");
}*/
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

// For simplicity, this function do simple operation.
// In the realistic scenario, key creation, signature generation and etc will be
// the possible example.
void do_secret(char *buf) 
{
    buf[VALUE_SIZE-2] = '0';
    buf[VALUE_SIZE-1] = '0';
}
void send_ea(int fd_ea, char *buf)
{
    int _kv_command_len = strlen(buf);
    write(fd_ea, &_kv_command_len, sizeof(int));
    write(fd_ea, buf, _kv_command_len+1);

}
int receive_ae(int fd_ae, char* buf)
{
    int _complete_len;
    read(fd_ae, &_complete_len, sizeof(int));
    read(fd_ae, buf, _complete_len+1);

    return _complete_len;
}
/* main operation. communicate with tor-gencert & tor process */
void enclave_main(int argc, char **argv)
{
    srand(time(0));

    int fd_ea = -1;
    int fd_ae = -1;

    char port_enc_to_app[NAME_BUF_SIZE];
    char port_app_to_enc[NAME_BUF_SIZE];

    if(argc != 4) {
        printf("Usage: ./test.sh sgx-tor [PORT_ENCLAVE_TO_APP] [PORT_APP_TO_ENCLAVE]\n");
        sgx_exit(NULL);
    }
    
    strcpy(port_enc_to_app, argv[2]);
    strcpy(port_app_to_enc, argv[3]);

    if(pipe_init(0) < 0) {
            puts("Error in pipe_init");
            sgx_exit(NULL);
    }

    if((fd_ea = pipe_open(port_enc_to_app, RB_MODE_WR, 0)) < 0) {
            puts("Error in pipe_open");
            sgx_exit(NULL);
    }

    if((fd_ae = pipe_open(port_app_to_enc, RB_MODE_RD, 0)) < 0) {
            puts("Error in pipe_open");
            sgx_exit(NULL);
    }

    MemTable_Init();
    SSTable_Init();

    // MDH
    FILE* fp;
    int err=0;
    char tmp_buf[20];
    int cpl_len;
    unsigned char key[5];
    unsigned char value[VALUE_SIZE+1]; // 1Byte * 64 = 64B
    unsigned char hmac[DIGEST_SIZE];
    unsigned int MemTable_Compaction_count = 0;
    unsigned int SSTable_Compaction_count = 0;

    fp = fopen("key_list","w");
    // Send KV to Non enclave.
    for( int i=0 ; i<ROUND ; i++){
        send_ea(fd_ea, "PUT");

        /* Key */
        for( int j=0 ; j<4 ; j++)
            key[j] = HEX_char[rand()%16];
        key[4] = '\0';
        write (fd_ea, key, 4);
        fprintf(fp, "%s\n", key);

        /* Value */
        for(int j=0 ; j<VALUE_SIZE ; j++)
            value[j] = HEX_char[rand()%16];
        value[VALUE_SIZE] = '\0';
        write(fd_ea, value, VALUE_SIZE);

        /* HMAC */
        sha512(value, VALUE_SIZE, hmac, 0);
        for( int i=0 ; i<DIGEST_SIZE ; i++)
            hmac[i] = HEX_char[rand()%16];
        write(fd_ea, hmac, DIGEST_SIZE);
        /* MemTable Flush (MemTable Compaction) */
        
        if( Is_MemTable_Full()){
            //printf("MemTable Full!!!!\n");
            MemTable_Compaction();
            MemTable_Compaction_count++;

            //SSTable_Print();
            //SSTable_Fin();
        }
        //printf("(%s) MemTable Insertion!!!\n", key);
        MemTable_Insertion(key, hmac);
        //MemTable_Print();
        
        /* SSTable Compaction Condition Check */
        
        
        int retry = Is_SSTable_FULL(&SSTable_Compaction_count);
        while(retry == 1)
            retry = Is_SSTable_FULL(&SSTable_Compaction_count);
        
        // COMPLETE signal Interrupt      
        cpl_len = receive_ae(fd_ae, tmp_buf);
        if( strncmp(tmp_buf, "COMPLETE", cpl_len)){
            err = 1;
            break;
        }
        if( i%1000 == 0) printf("%d\n",i);
    }

    //SSTable_Print();

    if(!err){
        receive_ae(fd_ae, tmp_buf);
        printf("%s\n", tmp_buf);
        fclose(fp);
    }
    else printf("ERROR\n");
    /* Print */
    //MemTable_Print();
    //SSTable_Print();

    MemTable_Fin();
    printf("MemTable Finished\n");
    SSTable_Fin();
    printf("SSTable Finished\n");
    printf("Mem Compaction cnt: %d\n", MemTable_Compaction_count);
    printf("SST Compaction cnt: %d\n", SSTable_Compaction_count);
    close(fd_ea);
    close(fd_ae);
}
