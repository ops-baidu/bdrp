/********************
Create time:2013-12-16 00:47
Author:hudongxu01@baidu.com
Usage:Whitelist function->just 4 protection && the anthorization of  read/write permission
Notice:The files of nutcracker,which contain nc_request.c,nc_message.h nc_server.h nc.c has been modified,Makefile is including too
********************/

#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <sys/time.h>

#include <nc_core.h>
#include <nc_whitelist.h>

proxy_atomic_t wl_num_tag = ATOMIC_INIT( (1 << (sizeof(uint32_t) * 8 - WL_TAG_BITS)) | 0 );

time_t last_modification = 0;
time_t bns_last_modification =0;
struct proxyWhitelist proxy_w_list;    /* connect whitelist */
struct timeval old,new;
int force_to_read_whitelist = 0;
int force_to_read_bns = 0;

static rstatus_t 
compare(const void* a,const void* b) {
    return *(uint32_t *)b - *(uint32_t *)a;
}

rstatus_t 
nc_ip_verify(int fd, int* type) {
    err_t ret = 0;
    struct sockaddr sa;
    socklen_t addr_len = sizeof(struct sockaddr_in);

    ret = getpeername(fd,&sa,&addr_len);
    if (ret != 0) {
        log_warn("Failed to invoke getpeername function");
        return NC_ERROR;
    }
    uint32_t ip_to_num = inet_network(inet_ntoa(((struct sockaddr_in *)&sa)->sin_addr));
    
    return nc_bsearch(ip_to_num, type);
}

rstatus_t 
nc_bsearch(uint32_t num, int* type) {
    int whitelist_tag = -1;
    int whitelist_element_num = -1;
    perm_t* w_list = NULL;

    uint32_t wl_num_tag_2_int = proxy_atomic_read(&wl_num_tag);
    whitelist_tag = wl_num_tag_2_int >> (sizeof(uint32_t) * 8 - WL_TAG_BITS);
    whitelist_element_num = (wl_num_tag_2_int << WL_TAG_BITS) >> WL_TAG_BITS;

    if (whitelist_tag == 0) {
        w_list = proxy_w_list.whitelist;
    } else if (whitelist_tag == 1) {
        w_list = proxy_w_list.whitelist_switch;
    }

    void* hit = bsearch((const void*)&num,(const void*)w_list, (size_t)whitelist_element_num, sizeof(perm_t), compare);
    if (hit) {
        perm_t* permt = (perm_t*)hit;
        *type = permt->perm;
        return NC_OK;
    }
    else {
        return NC_ERROR;
    }
}

void 
nc_get_whitelist(struct instance* nci) {
    if (nci->whitelist == 1) {
        pthread_t thread;

        if(pthread_create(&thread,NULL,intervalGetWhitelist,(void *)nci) != 0)
        {
            log_warn("Fatal:Can't initialize the whitelist thread.");
            exit(1);
        }
        return;
    }
    loga("whitelist : off,nc_get_whitelist thread exit now");
    return;
}

static rstatus_t 
nc_get_bns_name(char* file_name,char* bns) {
    int file_length = strlen(file_name);
    if(file_length < MAXLEN) {
        strncpy(bns,file_name,strlen(file_name));
        if (dirname(bns) != NULL) { 
            strcat(bns,"/bns");    
        } else {
            log_warn("cannot get the bns file when executing strcat function");
            return NC_ERROR;
        }
    } else {
        log_warn("the filename is too long");
        return NC_ERROR;
    }

    return NC_OK;
}

void* 
intervalGetWhitelist(void* arg) {
    /* Using detach to avoid the possibility of memory leakage */
    pthread_detach(pthread_self());

    struct instance *nci;
    nci = (struct instance *)arg;
    err_t err = 0;
    char bns[MAXLEN] = "0";

    gettimeofday(&old,NULL);
    err = nc_get_bns_name(nci->whitelist_filename, bns);
    if (err == -1) {
        loga("Failed to get the name of bns-whitelist");
    } else {
        loga("Success to get the name of bns:[%s]",bns);
    }

    while (1) {
        if (nci->whitelist == 1) {
            err = _intervalGetWhitelist(arg, CONN_WL_UPDATE, bns, nci->whitelist_filename);
            if (err == -1) {
                //nci->whitelist = 0;
                log_warn("Ip/bns whitelist update failed!Turn off the function of whitelist,whitelist thread exit now"); 
            }
        }
        sleep(2);
    } 
}

static uint32_t 
nc_get_perm(void* buf) {
    int buf_len = strlen(buf);
    if (buf_len < 1) {
        log_warn("perm buf size invalid");
        return PERM_NONE;
    }
    size_t cmp_len = 2;
    if (nc_strncmp(buf, "rw", cmp_len) == 0) {
        return ( PERM_R | PERM_W);
    }
    if (nc_strncmp(buf, "wr", cmp_len) == 0) {
        return ( PERM_R | PERM_W);
    }
    cmp_len = 1;
    if (nc_strncmp(buf, "r", cmp_len) == 0) {
        return PERM_R;
    }
    if (nc_strncmp(buf, "w", cmp_len) == 0) {
        return PERM_W;
    }
    return PERM_NONE;
}

static rstatus_t 
nc_check_ipwhitelist (char* file_name) {
    if(access(file_name,R_OK|F_OK) == -1) {
        log_warn("The whitelist(%s) doesn't exist or cannot be readed!The file of whitelist should be included!", file_name); 
        return NC_ERROR;
    } else {
        struct stat statbuff;
        if(stat(file_name,&statbuff) < 0) {
            log_warn("Failed to get the stat of whitelist file [%s]!", file_name);
            return NC_ERROR;
        } else {
            if(last_modification != statbuff.st_mtime) {
                last_modification = statbuff.st_mtime;
                return NC_OK;
            } else {
                return NC_ERROR;
            }
        }
    }
}

static rstatus_t 
nc_check_bns_file_timestamp(char* file_name) {
    struct stat statbuff;
    if(stat(file_name,&statbuff) < 0) {
        log_warn("Failed to get the stat of whitelist file [%s]!",file_name);
        return NC_ERROR;
    } else {
        if(bns_last_modification != statbuff.st_mtime) {
            bns_last_modification = statbuff.st_mtime; /* timestamp changed */
            return NC_OK;
        } else {
            return NC_ERROR;  /* no change */
        }
    }
}

static rstatus_t 
nc_check_bns_file_exist(char* file_name) {
    if(access(file_name,R_OK|F_OK) == -1) {
        log_warn("The BNS_whitelist(%s) doesn't exist or cannot be readed!", file_name); 
        return NC_ERROR;
    }
    return NC_OK;
}

static rstatus_t 
nc_read_ip_whitelist(uint32_t* next_tag,uint32_t* wl_num_tag_temp,uint32_t* whitelist_tag,char* file_name,char* bns,perm_t** w_list,uint32_t* cnt) {
    if (nc_check_ipwhitelist(file_name) != -1 || force_to_read_whitelist == 1 || nc_check_bns_file_timestamp(bns) != -1) {
        force_to_read_bns = 1;    
        
        FILE *white_list_fd = fopen(file_name,"r");
        if(white_list_fd == NULL) {
            log_warn("Failed to open the whitelist file[%s]!", file_name);
            return NC_ERROR;
        } else {
            char buf[100]="0";
            
            /* deal with ipwhitelist */
            while (fgets(buf, (int)sizeof(buf), white_list_fd)) {
                if(strchr("\n\r#", *buf))
                    continue;
                if(*cnt >= WHITELIST_MAX_NUMS) {
                    log_warn("the number of ip in file [%s] is more than iplist_max, [max:%d]", 
                            file_name, WHITELIST_MAX_NUMS);
                    break;
                }

                char *p_parse  = strtok(buf, " \t\n\r");
                int  field_cnt = 0;
                uint32_t perm;

                while (p_parse) {
                    if (field_cnt == 0)
                        (*w_list)[*cnt].ip = inet_network(p_parse);
                    else if (field_cnt == 1) {
                        perm = nc_get_perm(p_parse);
                        if (perm == PERM_NONE) {
                            field_cnt = 3;
                            break;
                        }
                        (*w_list)[*cnt].perm = perm;
                    }
					else {
						log_warn("configure bad format[egg:ip rw]");
                        field_cnt = 3;
                        break;
					}
                    p_parse = strtok(NULL, " \t\n\r");
                    field_cnt++;
                }

                if (field_cnt == 2)
				    (*cnt)++;
            }
            fclose(white_list_fd);        
        }
        if (force_to_read_whitelist == 1){
            qsort(*w_list, (size_t)*cnt, sizeof(perm_t), compare);
            *wl_num_tag_temp = (*next_tag << (sizeof(uint32_t) * 8 - WL_TAG_BITS)) | *cnt;
            proxy_atomic_set(&wl_num_tag,*wl_num_tag_temp);    
            loga("[Trigger by whitelist reading]whitelist and BNS updated, tag: %d, elements_num:%d",*next_tag, *cnt);
        }
    }
    return NC_OK;
}

static rstatus_t 
nc_read_bns_whitelist(uint32_t* next_tag,uint32_t* wl_num_tag_temp,uint32_t* whitelist_tag,char* file_name,char* bns,perm_t** w_list,uint32_t* cnt) {
    int tick;

    if (nc_check_bns_file_exist(bns) != -1) {
        gettimeofday(&new,NULL);
        tick = 1000000 * (new.tv_sec - old.tv_sec) + new.tv_usec - old.tv_usec;

        /* trigger the timer or force to read bns */
        if (tick >= BNS_PERIOD || force_to_read_bns == 1) {
            if (tick >= BNS_PERIOD)
                force_to_read_whitelist =1; /* force to read the whitelist due the tick is reaching! */
            else {
                if (force_to_read_bns ==1)
                    force_to_read_whitelist = 0;
            }
            gettimeofday(&old,NULL);
            
            FILE *bns_fd = fopen(bns,"r");
            if(bns_fd == NULL) {
                log_warn("Failed to open the BNS whitelist file[%s]!", bns);
                return NC_ERROR;
            }

            /* deal with bnswhitelist */
            char buf[BNS_BUF];
            char tmp_buf[BNS_STORAGE]; 
            while (fgets(buf, (int)sizeof(buf), bns_fd) != NULL) {
                if(strchr("\n\r#", *buf))
                    continue;
                if(*cnt >= WHITELIST_MAX_NUMS) {
                    log_warn("the number of ip in bns and whitelist is more than iplist_max, [max:%d]", 
                             WHITELIST_MAX_NUMS);
                    break;
                }

                char *p_bns_pos = NULL;
                char *p_parse  = strtok(buf, " \t\n\r");
                int  field_cnt = 0;
                uint32_t perm = 1;

                while (p_parse) {
                    if (field_cnt == 0) {
                        p_bns_pos = p_parse;
                    }
                    else if (field_cnt == 1) {
                        perm = nc_get_perm(p_parse);
                    }
					else {
						log_warn("configure bad format[egg:ip rw]");
                        field_cnt++;
                        break;
					}
                    p_parse = strtok(NULL, " \t\n\r");
                    field_cnt++;
                }

                if (field_cnt == 2 && perm != PERM_NONE)
                {
                    FILE *pipe_ptr = NULL;
                    char command[100] = "0";
                    strncpy(command,BNS_COMMAND,strlen(BNS_COMMAND));
                    sprintf(command,"get_instance_by_service %s -i 2>&1 | cut -d ' ' -f2",p_bns_pos); 
                    if ((pipe_ptr=popen(command,"r")) != NULL) {
                        while (fgets(tmp_buf, (int)sizeof(tmp_buf), pipe_ptr) != NULL) {
                            if (nc_strncmp(tmp_buf, BNS_WRONG, strlen(BNS_WRONG)) == 0) {
                                log_warn("The BNS name cannot be analyzed:%s",p_bns_pos);
                                break;
                            }                
                            tmp_buf[strlen(tmp_buf) - 1] = '\0';  
                            (*w_list)[*cnt].ip = inet_network(tmp_buf);
                            (*w_list)[*cnt].perm = perm;
                            (*cnt)++;
                        }    
                        pclose(pipe_ptr);
                        pipe_ptr = NULL;
                    }
                    else {
                        log_warn("Fail to call popen function:%s",strerror(errno));
                    }
                }
            }
            fclose(bns_fd);        
        }

        if (force_to_read_bns == 1) {
            qsort(*w_list, (size_t)*cnt, sizeof(perm_t), compare);
            *wl_num_tag_temp = (*next_tag << (sizeof(uint32_t) * 8 - WL_TAG_BITS)) | *cnt;
            proxy_atomic_set(&wl_num_tag,*wl_num_tag_temp);
            loga("[Trigger by BNS reading]whitelist and bns whitelist updated, tag: %d, elements_num:%d", *next_tag, *cnt);
        }
    }
	else {
		return NC_ERROR;
	}
    /******
     force to read the whitelist no matter the 
      timestamp of whitelist is modified or not,
       but if the whitelist has been read just now,
      we will avoid read the whitelist again. 
    ******/
    if (force_to_read_bns == 0 && force_to_read_whitelist == 1) {
        nc_read_ip_whitelist(next_tag,wl_num_tag_temp,whitelist_tag,file_name,bns,w_list,cnt);
    }
    return NC_OK;
}

rstatus_t 
_intervalGetWhitelist(void* arg, int type ,char* bns ,char* file_name) {
	int ret;
    uint32_t next_tag = 0;
    uint32_t wl_num_tag_temp = 0;
    uint32_t whitelist_tag = 0;
    perm_t* w_list = NULL;
    uint32_t cnt = 0;
    force_to_read_whitelist = 0;
    force_to_read_bns = 0;

    uint32_t wl_num_tag_2_int = proxy_atomic_read(&wl_num_tag);    
    whitelist_tag = wl_num_tag_2_int >> (sizeof(uint32_t) * 8 - WL_TAG_BITS);

    if (whitelist_tag == 0) {
        w_list = proxy_w_list.whitelist_switch;
        next_tag = 1;
    } else if (whitelist_tag == 1) {
        w_list = proxy_w_list.whitelist;
        next_tag = 0;
    } else {
        log_warn("Wrong tag:%d!Exit now",whitelist_tag);
        return NC_ERROR;
    }

    ret = nc_read_ip_whitelist(&next_tag,&wl_num_tag_temp,&whitelist_tag,file_name,bns,&w_list,&cnt);
    if (ret == -1)
        return NC_ERROR;

    ret = nc_read_bns_whitelist(&next_tag,&wl_num_tag_temp,&whitelist_tag,file_name,bns,&w_list,&cnt);
    if (ret == -1)
        return NC_ERROR;
    
    return NC_OK;
}
