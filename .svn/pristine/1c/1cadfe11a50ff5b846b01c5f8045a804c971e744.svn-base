/******************
Create time:2013-8-13 14:47
Author:hudongxu01@baidu.com
Usage:Whitelist function->just 4 protection
******************/

#ifndef __WHITELIST_H__
#define __WHITELIST_H__

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "nc_core.h"


/******************************
      Extern declarations 
******************************/


#define WHITELIST_ON        1
#define WHITELIST_OFF        0

#define CONN_PERM_CHECK        0
#define WRITE_PERM_CHECK    1

#define PERM_NONE    0

#define WHITELIST_MAX_NUMS 10000
#define WL_TAG_BITS            1

#define CONN_WL_UPDATE    0
#define WRITE_WL_UPDATE    1

#define BNS_PERIOD 5*60*1000000 // 5 minutes
#define MAXLEN 1024
#define BNS_BUF 255
#define BNS_STORAGE 100
#define BNS_COMMAND "get_instance_by_service"
#define BNS_WRONG "service not exist"

#define proxy_atomic_read(v) (*(volatile uint32_t *)&(v)->counter)
#define proxy_atomic_set(v,i) (((v)->counter) = (i))
#define ATOMIC_INIT(i)  { (uint32_t)(i) }

typedef struct perm_s {
    uint32_t ip;
    uint32_t perm;
} perm_t;

struct proxyWhitelist{
    perm_t whitelist[WHITELIST_MAX_NUMS];
    perm_t whitelist_switch[WHITELIST_MAX_NUMS];
};

//The assignment of INT can be taken as atomic operation with "VOLATILE"
typedef struct {
    volatile uint32_t counter;
}proxy_atomic_t;

void nc_get_whitelist(struct instance* nci);
void* intervalGetWhitelist(void* arg);
rstatus_t _intervalGetWhitelist(void* arg, int type, char* bns, char* file_name);
rstatus_t nc_ip_verify(int fd, int* type);
rstatus_t nc_bsearch(uint32_t num, int* type);

#endif
