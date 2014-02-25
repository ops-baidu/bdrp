/*
 * twemproxy - A fast and lightweight proxy for memcached protocol.
 * Copyright (C) 2011 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _NC_MESSAGE_H_
#define _NC_MESSAGE_H_

#include <nc_core.h>

#define PERM_R   ( 0x1 << 28 )   //the highest 4 bits are:0001(unsigned int)
#define PERM_W   ( 0x1 << 29 )   //the highest 4 bits are:0010(unsigned int)

#define MSG_INFO_SENTINEL_STRING       "*2\r\n$4\r\ninfo\r\n$8\r\nsentinel\r\n"
#define MSG_INFO_REPLICATION_STRING       "*2\r\n$4\r\ninfo\r\n$11\r\nreplication\r\n"
#define MSG_SUB_SWITCH_STRING "*2\r\n$10\r\nPSUBSCRIBE\r\n$14\r\n+switch-master\r\n"

typedef void (*msg_parse_t)(struct msg *);
typedef rstatus_t (*msg_post_splitcopy_t)(struct msg *);
typedef void (*msg_coalesce_t)(struct msg *r);

typedef enum msg_parse_result {
    MSG_PARSE_OK,                         /* parsing ok */
    MSG_PARSE_ERROR,                      /* parsing error */
    MSG_PARSE_UNAUTHORIZATION,            /* the permission is not corresponding to the ip's perm*/
    MSG_PARSE_REPAIR,                     /* more to parse -> repair parsed & unparsed data */
    MSG_PARSE_FRAGMENT,                   /* multi-vector request -> fragment */
    MSG_PARSE_AGAIN,                      /* incomplete -> parse again */
} msg_parse_result_t;

typedef enum msg_type {
    MSG_UNKNOWN = 0,
    MSG_REQ_REDIS_DEL = PERM_W | 1,                    /* redis commands - keys */
    MSG_REQ_REDIS_EXISTS = PERM_R | 2,
    MSG_REQ_REDIS_EXPIRE = PERM_W | 3,
    MSG_REQ_REDIS_EXPIREAT = PERM_W | 4,
    MSG_REQ_REDIS_PEXPIRE = PERM_W | 5,
    MSG_REQ_REDIS_PEXPIREAT = PERM_W | 6,
    MSG_REQ_REDIS_PERSIST = PERM_W | 7,
    MSG_REQ_REDIS_PTTL = PERM_R | 8,
    MSG_REQ_REDIS_TTL = PERM_R | 9,
    MSG_REQ_REDIS_TYPE =  PERM_R | 10,
    MSG_REQ_REDIS_APPEND = PERM_W | 11,                 /* redis requests - string */
    MSG_REQ_REDIS_BITCOUNT = PERM_R | 12,
    MSG_REQ_REDIS_DECR = PERM_W | 13,
    MSG_REQ_REDIS_DECRBY = PERM_W | 14,
    MSG_REQ_REDIS_DUMP = PERM_R | 15,
    MSG_REQ_REDIS_GET = PERM_R | 16,
    MSG_REQ_REDIS_GETBIT = PERM_R | 17,
    MSG_REQ_REDIS_GETRANGE = PERM_R | 18,
    MSG_REQ_REDIS_GETSET = PERM_W | 19,
    MSG_REQ_REDIS_INCR = PERM_W | 20,
    MSG_REQ_REDIS_INCRBY = PERM_W | 21,
    MSG_REQ_REDIS_INCRBYFLOAT = PERM_W |22,
    MSG_REQ_REDIS_MGET = PERM_R | 23,
    MSG_REQ_REDIS_PSETEX = PERM_W | 24,
    MSG_REQ_REDIS_RESTORE = PERM_W | 25,
    MSG_REQ_REDIS_SET = PERM_W | 26,
    MSG_REQ_REDIS_SETBIT = PERM_W | 27,
    MSG_REQ_REDIS_SETEX = PERM_W | 28,
    MSG_REQ_REDIS_SETNX = PERM_W | 29,
    MSG_REQ_REDIS_SETRANGE = PERM_W | 30,
    MSG_REQ_REDIS_STRLEN = PERM_W | 31,
    MSG_REQ_REDIS_HDEL = PERM_W | 32,                   /* redis requests - hashes */
    MSG_REQ_REDIS_HEXISTS = PERM_R | 33,
    MSG_REQ_REDIS_HGET = PERM_R | 34,
    MSG_REQ_REDIS_HGETALL = PERM_R | 35,
    MSG_REQ_REDIS_HINCRBY =  PERM_W | 36,
    MSG_REQ_REDIS_HINCRBYFLOAT = PERM_W | 37,
    MSG_REQ_REDIS_HKEYS = PERM_R | 38,
    MSG_REQ_REDIS_HLEN = PERM_R | 39,
    MSG_REQ_REDIS_HMGET = PERM_R | 40,
    MSG_REQ_REDIS_HMSET = PERM_W | 41,
    MSG_REQ_REDIS_HSET = PERM_W | 42,
    MSG_REQ_REDIS_HSETNX = PERM_W | 43,
    MSG_REQ_REDIS_HVALS = PERM_R | 44,
    MSG_REQ_REDIS_LINDEX = PERM_R | 45,                 /* redis requests - lists */
    MSG_REQ_REDIS_LINSERT = PERM_W | 46,
    MSG_REQ_REDIS_LLEN = PERM_R | 47,
    MSG_REQ_REDIS_LPOP = PERM_W | 48,
    MSG_REQ_REDIS_LPUSH = PERM_W | 49,
    MSG_REQ_REDIS_LPUSHX = PERM_W | 50,
    MSG_REQ_REDIS_LRANGE = PERM_R | 51,
    MSG_REQ_REDIS_LREM = PERM_W | 52,
    MSG_REQ_REDIS_LSET = PERM_W | 53,
    MSG_REQ_REDIS_LTRIM =  PERM_W | 54,
    MSG_REQ_REDIS_RPOP = PERM_W | 55,
    MSG_REQ_REDIS_RPOPLPUSH = PERM_W | 56,
    MSG_REQ_REDIS_RPUSH = PERM_W | 57,
    MSG_REQ_REDIS_RPUSHX = PERM_W | 58,
    MSG_REQ_REDIS_SADD = PERM_W | 59,                   /* redis requests - sets */
    MSG_REQ_REDIS_SCARD = PERM_R | 60,
    MSG_REQ_REDIS_SDIFF = PERM_R | 61,
    MSG_REQ_REDIS_SDIFFSTORE = PERM_W | 62,
    MSG_REQ_REDIS_SINTER = PERM_R | 63,
    MSG_REQ_REDIS_SINTERSTORE = PERM_W | 64,
    MSG_REQ_REDIS_SISMEMBER = PERM_R | 65,
    MSG_REQ_REDIS_SMEMBERS = PERM_R | 66,
    MSG_REQ_REDIS_SMOVE = PERM_W | 67,
    MSG_REQ_REDIS_SPOP = PERM_W | 68,
    MSG_REQ_REDIS_SRANDMEMBER = PERM_R | 69,
    MSG_REQ_REDIS_SREM = PERM_W | 70,
    MSG_REQ_REDIS_SUNION = PERM_R | 71,
    MSG_REQ_REDIS_SUNIONSTORE = PERM_W | 72,
    MSG_REQ_REDIS_ZADD = PERM_W | 73,                   /* redis requests - sorted sets */
    MSG_REQ_REDIS_ZCARD = PERM_R | 74,
    MSG_REQ_REDIS_ZCOUNT = PERM_R | 75,
    MSG_REQ_REDIS_ZINCRBY = PERM_W | 76,
    MSG_REQ_REDIS_ZINTERSTORE = PERM_W | 77,
    MSG_REQ_REDIS_ZRANGE = PERM_R | 78,
    MSG_REQ_REDIS_ZRANGEBYSCORE = PERM_R | 79,
    MSG_REQ_REDIS_ZRANK = PERM_W | 80,
    MSG_REQ_REDIS_ZREM = PERM_W | 81,
    MSG_REQ_REDIS_ZREMRANGEBYRANK = PERM_W | 82,
    MSG_REQ_REDIS_ZREMRANGEBYSCORE = PERM_W | 83,
    MSG_REQ_REDIS_ZREVRANGE = PERM_R | 84,
    MSG_REQ_REDIS_ZREVRANGEBYSCORE = PERM_R | 85,
    MSG_REQ_REDIS_ZREVRANK = PERM_R | 86,
    MSG_REQ_REDIS_ZSCORE = PERM_R | 87,
    MSG_REQ_REDIS_ZUNIONSTORE = PERM_W | 88,
    MSG_REQ_REDIS_EVAL = PERM_W | 89,                   /* redis requests - eval */
    MSG_REQ_REDIS_EVALSHA = PERM_W | 90,
    MSG_RSP_REDIS_STATUS,                 /* redis response */
    MSG_RSP_REDIS_ERROR,
    MSG_RSP_REDIS_INTEGER,
    MSG_RSP_REDIS_BULK,
    MSG_RSP_REDIS_MULTIBULK,
	/***The types of command are referred to MEMCACHE****/
    MSG_REQ_MC_GET,                       /* memcache retrieval requests */
    MSG_REQ_MC_GETS,
    MSG_REQ_MC_DELETE,                    /* memcache delete request */
    MSG_REQ_MC_CAS,                       /* memcache cas request and storage request */
    MSG_REQ_MC_SET,                       /* memcache storage request */
    MSG_REQ_MC_ADD,
    MSG_REQ_MC_REPLACE,
    MSG_REQ_MC_APPEND,
    MSG_REQ_MC_PREPEND,
    MSG_REQ_MC_INCR,                      /* memcache arithmetic request */
    MSG_REQ_MC_DECR,
    MSG_REQ_MC_QUIT,                      /* memcache quit request */
    MSG_RSP_MC_NUM,                       /* memcache arithmetic response */
    MSG_RSP_MC_STORED,                    /* memcache cas and storage response */
    MSG_RSP_MC_NOT_STORED,
    MSG_RSP_MC_EXISTS,
    MSG_RSP_MC_NOT_FOUND,
    MSG_RSP_MC_END,
    MSG_RSP_MC_VALUE,
    MSG_RSP_MC_DELETED,                   /* memcache delete response */
    MSG_RSP_MC_ERROR,                     /* memcache error responses */
    MSG_RSP_MC_CLIENT_ERROR,
    MSG_RSP_MC_SERVER_ERROR,
	/**** memcache type END****/
    MSG_SENTINEL = 0x7fffffff             /* signed INT_MAX */
} msg_type_t;

struct msg {
    TAILQ_ENTRY(msg)     c_tqe;           /* link in client q */
    TAILQ_ENTRY(msg)     s_tqe;           /* link in server q */
    TAILQ_ENTRY(msg)     m_tqe;           /* link in send q / free q */

    uint64_t             id;              /* message id */
    struct msg           *peer;           /* message peer */
    struct conn          *owner;          /* message owner - client | server */

    struct rbnode        tmo_rbe;         /* entry in rbtree */

    struct mhdr          mhdr;            /* message mbuf header */
    uint32_t             mlen;            /* message length */

    int                  state;           /* current parser state */
    uint8_t              *pos;            /* parser position marker */
    uint8_t              *token;          /* token marker */

    msg_parse_t          parser;          /* message parser */
    msg_parse_result_t   result;          /* message parsing result */

    mbuf_copy_t          pre_splitcopy;   /* message pre-split copy */
    msg_post_splitcopy_t post_splitcopy;  /* message post-split copy */
    msg_coalesce_t       pre_coalesce;    /* message pre-coalesce */
    msg_coalesce_t       post_coalesce;   /* message post-coalesce */

    msg_type_t           type;            /* message type */

    uint8_t              *key_start;      /* key start */
    uint8_t              *key_end;        /* key end */

    uint32_t             vlen;            /* value length (memcache) */
    uint8_t              *end;            /* end marker (memcache) */

    uint8_t              *narg_start;     /* narg start (redis) */
    uint8_t              *narg_end;       /* narg end (redis) */
    uint32_t             narg;            /* # arguments (redis) */
    uint32_t             rnarg;           /* running # arg used by parsing fsa (redis) */
    uint32_t             rlen;            /* running length in parsing fsa (redis) */
    uint32_t             integer;         /* integer reply value (redis) */

    struct msg           *frag_owner;     /* owner of fragment message */
    uint32_t             nfrag;           /* # fragment */
    uint64_t             frag_id;         /* id of fragmented message */

    err_t                err;             /* errno on error? */
    unsigned             error:1;         /* error? */
    unsigned             ferror:1;        /* one or more fragments are in error? */
    unsigned             request:1;       /* request? or response? */
    unsigned             quit:1;          /* quit request? */
    unsigned             noreply:1;       /* noreply? */
    unsigned             done:1;          /* done? */
    unsigned             fdone:1;         /* all fragments are done? */
    unsigned             first_fragment:1;/* first fragment? */
    unsigned             last_fragment:1; /* last fragment? */
    unsigned             swallow:1;       /* swallow response? */
    unsigned             redis:1;         /* redis? */
};

TAILQ_HEAD(msg_tqh, msg);

struct msg *msg_tmo_min(void);
void msg_tmo_insert(struct msg *msg, struct conn *conn);
void msg_tmo_delete(struct msg *msg);

void msg_init(void);
void msg_deinit(void);
struct msg *msg_get(struct conn *conn, bool request, bool redis);
void msg_put(struct msg *msg);
struct msg *msg_get_error(bool redis, err_t err);
void msg_dump(struct msg *msg);
bool msg_empty(struct msg *msg);
void msg_read_line(struct msg* msg, struct mbuf *line_buf, int line_num);
rstatus_t msg_recv(struct context *ctx, struct conn *conn);
rstatus_t msg_send(struct context *ctx, struct conn *conn);

struct msg *req_get(struct conn *conn);
void req_put(struct msg *msg);
bool req_done(struct conn *conn, struct msg *msg);
bool req_error(struct conn *conn, struct msg *msg);
void req_server_enqueue_imsgq(struct context *ctx, struct conn *conn, struct msg *msg);
void req_server_dequeue_imsgq(struct context *ctx, struct conn *conn, struct msg *msg);
void req_client_enqueue_omsgq(struct context *ctx, struct conn *conn, struct msg *msg);
void req_server_enqueue_omsgq(struct context *ctx, struct conn *conn, struct msg *msg);
void req_client_dequeue_omsgq(struct context *ctx, struct conn *conn, struct msg *msg);
void req_server_dequeue_omsgq(struct context *ctx, struct conn *conn, struct msg *msg);
struct msg *req_recv_next(struct context *ctx, struct conn *conn, bool alloc);
void req_recv_done(struct context *ctx, struct conn *conn, struct msg *msg, struct msg *nmsg);
struct msg *req_send_next(struct context *ctx, struct conn *conn);
void req_send_done(struct context *ctx, struct conn *conn, struct msg *msg);
rstatus_t req_construct(struct context *ctx, struct conn *conn, char *cmd_str);

struct msg *rsp_get(struct conn *conn);
void rsp_put(struct msg *msg);
struct msg *rsp_recv_next(struct context *ctx, struct conn *conn, bool alloc);
void rsp_recv_done(struct context *ctx, struct conn *conn, struct msg *msg, struct msg *nmsg);
struct msg *rsp_send_next(struct context *ctx, struct conn *conn);
void rsp_send_done(struct context *ctx, struct conn *conn, struct msg *msg);

#endif
