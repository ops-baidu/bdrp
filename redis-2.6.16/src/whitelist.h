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


/******************************
      Extern declarations 
******************************/


#define WHITELIST_ON		1
#define WHITELIST_OFF		0

#define CONN_PERM_CHECK		0
#define WRITE_PERM_CHECK	1

#define PERM_NONE	0
#define PERM_R		1
#define PERM_W		2
#define PERM_RW		3

//extern struct redisWhitelist w_list;
//extern time_t last_modification; 
//extern int whitelist_element_num;
//extern int whitelist_tag __attribute__ ((weakref));
//extern int whitelist_tag;
//int compare(const void *a,const void *b);
//extern int binarySearch(unsigned int num);
//extern int binarySearch(unsigned int num) __attribute__ ((weak));
//extern int findWhitelist(struct sockaddr *sa,int fd) __attribute ((weak));
//extern void *intervalGetWhitelist(void *arg);

extern int findWhitelist(int fd, int type);
extern void whitelistJob();

#endif
