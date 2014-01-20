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

#include <stdlib.h>
#include <unistd.h>

#include <nc_core.h>
#include <nc_event.h>
#include <nc_server.h>
#include <nc_conf.h>

void
server_ref(struct conn *conn, void *owner)
{
    struct server *server = owner;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->owner == NULL);

    conn->family = server->family;
    conn->addrlen = server->addrlen;
    conn->addr = server->addr;

    server->ns_conn_q++;
    TAILQ_INSERT_TAIL(&server->s_conn_q, conn, conn_tqe);

    conn->owner = owner;

    log_debug(LOG_VVERB, "ref conn %p owner %p into '%.*s", conn, server,
              server->pname.len, server->pname.data);
}

void
server_unref(struct conn *conn)
{
    struct server *server;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->owner != NULL);

    server = conn->owner;
    conn->owner = NULL;

    ASSERT(server->ns_conn_q != 0);
    server->ns_conn_q--;
    TAILQ_REMOVE(&server->s_conn_q, conn, conn_tqe);

    log_debug(LOG_VVERB, "unref conn %p owner %p from '%.*s'", conn, server,
              server->pname.len, server->pname.data);
}

int
server_timeout(struct conn *conn)
{
    struct server *server;
    struct server_pool *pool;

    ASSERT(!conn->client && !conn->proxy);

    server = conn->owner;
    pool = server->owner;

    return pool->timeout;
}

bool
server_active(struct conn *conn)
{
    ASSERT(!conn->client && !conn->proxy);

    if (!TAILQ_EMPTY(&conn->imsg_q)) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    if (!TAILQ_EMPTY(&conn->omsg_q)) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    if (conn->rmsg != NULL) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    if (conn->smsg != NULL) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    log_debug(LOG_VVERB, "s %d is inactive", conn->sd);

    return false;
}

rstatus_t
server_each_set_master(void *elem, void *data)
{
    struct server *slave = elem;
    struct server *master = data;

    slave->master = master;

    return NC_OK;
}

static rstatus_t
server_each_set_owner(void *elem, void *data)
{
    rstatus_t status;
    struct server *s = elem;
    struct server_pool *sp = data;

    s->owner = sp;

    /* if the server is master, and has slaves,
     * set slaves's owner to the sp.
     */
    if (s->master == NULL && array_n(&s->slave) != 0) {
        status = array_each(&s->slave, server_each_set_owner, sp);
        if (status != NC_OK) {
            return status;
        }
    }

    return NC_OK;
}

rstatus_t
server_init(struct array *server, struct array *conf_server,
            struct server_pool *sp)
{
    rstatus_t status;
    uint32_t nserver;

    nserver = array_n(conf_server);
    ASSERT(nserver != 0);
    ASSERT(array_n(server) == 0);

    status = array_init(server, nserver, sizeof(struct server));
    if (status != NC_OK) {
        return status;
    }

    /* transform conf server to server */
    status = array_each(conf_server, conf_server_each_transform, server);
    if (status != NC_OK) {
        server_deinit(server);
        return status;
    }
    ASSERT(array_n(server) == nserver);

    /* set server owner */
    status = array_each(server, server_each_set_owner, sp);
    if (status != NC_OK) {
        server_deinit(server);
        return status;
    }

    log_debug(LOG_DEBUG, "init %"PRIu32" servers in pool %"PRIu32" '%.*s'",
              nserver, sp->idx, sp->name.len, sp->name.data);

    return NC_OK;
}

void
server_deinit(struct array *server)
{
    uint32_t i, nserver;

    for (i = 0, nserver = array_n(server); i < nserver; i++) {
        struct server *s;

        s = array_pop(server);
        ASSERT(TAILQ_EMPTY(&s->s_conn_q) && s->ns_conn_q == 0);

        if (s->master == NULL && array_n(&s->slave) != 0) {
            server_deinit(&s->slave);
        }
    }
    array_deinit(server);
}

struct conn *
server_conn(struct server *server)
{
    struct server_pool *pool;
    struct conn *conn;

    pool = server->owner;

    /*
     * FIXME: handle multiple server connections per server and do load
     * balancing on it. Support multiple algorithms for
     * 'server_connections:' > 0 key
     */

    if (server->ns_conn_q < pool->server_connections) {
        return conn_get(server, false, pool->redis);
    }
    ASSERT(server->ns_conn_q == pool->server_connections);

    /*
     * Pick a server connection from the head of the queue and insert
     * it back into the tail of queue to maintain the lru order
     */
    conn = TAILQ_FIRST(&server->s_conn_q);
    ASSERT(!conn->client && !conn->proxy);

    TAILQ_REMOVE(&server->s_conn_q, conn, conn_tqe);
    TAILQ_INSERT_TAIL(&server->s_conn_q, conn, conn_tqe);

    return conn;
}

static rstatus_t
server_each_preconnect(void *elem, void *data)
{
    rstatus_t status;
    struct server *server;
    struct server_pool *pool;
    struct conn *conn;

    server = elem;
    pool = server->owner;

    conn = server_conn(server);
    if (conn == NULL) {
        return NC_ENOMEM;
    }

    status = server_connect(pool->ctx, server, conn);
    if (status != NC_OK) {
        log_warn("connect to server '%.*s' failed, ignored: %s",
                 server->pname.len, server->pname.data, strerror(errno));
        server_close(pool->ctx, conn);
    }

    /* if the server is master, and has one more slaves, preconnect them */
    if (server->master == NULL && array_n(&server->slave) != 0) {
        status = array_each(&server->slave, server_each_preconnect, NULL);
        if (status != NC_OK) {
            return status;
        }
    }

    return NC_OK;
}

static rstatus_t
server_each_disconnect(void *elem, void *data)
{
    rstatus_t status;
    struct server *server;
    struct server_pool *pool;

    server = elem;
    pool = server->owner;

    while (!TAILQ_EMPTY(&server->s_conn_q)) {
        struct conn *conn;

        ASSERT(server->ns_conn_q > 0);

        conn = TAILQ_FIRST(&server->s_conn_q);
        conn->close(pool->ctx, conn);
    }

    /* if the server is master, and has one more slaves, disconnect them */
    if (server->master == NULL && array_n(&server->slave) != 0) {
        status = array_each(&server->slave, server_each_disconnect, NULL);
        if (status != NC_OK) {
            return status;
        }
    }

    return NC_OK;
}

/* used to disconnect  server's all conn in the timer.
 * do this in file event may be cause some problem
 */
int
server_disconnect(struct context *ctx, long long id, void *client_data)
{
    struct server *server = client_data;
    server_each_disconnect(server, NULL);

    return EVENT_TIMER_NOMORE;
}

static inline struct string
server_get_addr_from_pname(struct string *ppname)
{
    struct string addr;
    uint8_t *p, *end;

    addr.data = ppname->data;
    end = ppname->data + ppname->len - 1;
    p = nc_strrchr(end, ppname->data, ':');
    addr.len = p - ppname->data;

    return addr;
}

static int
server_address_compare(struct server *s1, struct server *s2)
{
    struct string s1_addr, s2_addr;

    s1_addr = server_get_addr_from_pname(&s1->pname);
    
    s2_addr = server_get_addr_from_pname(&s2->pname);

    return string_compare(&s1_addr, &s2_addr);
}

int
server_health_check(struct context *ctx, long long id, void *client_data)
{
    rstatus_t status;
    struct server *check_server;
    struct conn *conn;

    check_server = client_data;

    ASSERT(check_server->status == SERVER_STATUS_DISCONNECTED);

    /* pick a connection to a given server */
    conn = server_conn(check_server);
    if (conn == NULL) {
        return ctx->server_reconnect_interval;
    }

    status = server_connect(ctx, check_server, conn);
    if (status != NC_OK) {
        server_close(ctx, conn);
        return ctx->server_reconnect_interval;
    }

    status = req_construct(ctx, conn, MSG_INFO_REPLICATION_STRING);
    if(status != NC_OK) {
        server_close(ctx, conn);
        return ctx->server_reconnect_interval;
    }

    check_server->status = SERVER_STATUS_INFOSEND;

    return EVENT_TIMER_NOMORE;
}

void
server_proc_replication_info(struct context *ctx, struct conn *conn, struct msg *msg)
{
    rstatus_t status;
    struct server *server;
    struct string role_master, role_slave, slave_status_online, tmp_string;
    struct mbuf *line_buf;

    line_buf = NULL;

    string_init(&tmp_string);
    string_set_text(&role_master, "role:master");
    string_set_text(&role_slave, "role:slave");
    string_set_text(&slave_status_online, "master_link_status:up");

    server = conn->owner;

    /* if the status is not infosend, we know it's the alive conn's rsp
     * for the normal req before the server disconnect timer execute.
     * Just release the conn.
     */
    if (server->status != SERVER_STATUS_INFOSEND) {
        goto error;
    }

    line_buf = mbuf_get();
    if (line_buf == NULL) {
        goto error;
    }

    /* get redis role in replication info line 3 */
    msg_read_line(msg, line_buf, 3);
    if (mbuf_length(line_buf) == 0) {
        log_error("read line failed from redis ack info when skip line not used.");
        goto error;
    }
    log_debug(LOG_INFO, "server role line : %.*s", mbuf_length(line_buf), line_buf->pos);

    status = mbuf_read_string(line_buf, CR, &tmp_string);
    if (status != NC_OK) {
        goto error;
    }

    if (!string_compare(&role_master, &tmp_string)) {
        if (server_address_compare(server, server->master)) {
            goto error;
        } else {
            goto success;
        }
    }

    if (string_compare(&role_slave, &tmp_string)) {
        goto error;
    }
    
    /* get redis slave status line */
    msg_read_line(msg, line_buf, 3);
    if (mbuf_length(line_buf) == 0) {
        log_error("read line failed from redis ack info when skip line not used.");
        goto error;
    }
    log_debug(LOG_INFO, "slave status line : %.*s", mbuf_length(line_buf), line_buf->pos);

    status = mbuf_read_string(line_buf, CR, &tmp_string);
    if (status != NC_OK || string_compare(&slave_status_online, &tmp_string)) {
        goto error;
    }

    goto success;

done:
    if (line_buf != NULL) {
        mbuf_put(line_buf);
    }
    string_deinit(&tmp_string);
    rsp_put(msg);
    return;

success:
    server->status = SERVER_STATUS_ONLINE;
    server_ok(ctx, conn);
    log_warn("server %.*s health check rsp ok, make it online.",
             server->pname.len, server->pname.data);
    goto done;
    
error:
    log_error("server %.*s health check rsp error, close the conn.",
              server->pname.len, server->pname.data);
    conn->done = 1;
    goto done;
}

static void
server_failure(struct context *ctx, struct server *server)
{
    struct server_pool *pool = server->owner;
    int64_t now, next;
    rstatus_t status;

    /* sentinel server don't need to update server pool */
    if (server->owner == NULL) {
        return;
    }

    /* auto_eject_hosts is just used for master server */
    if (!pool->auto_eject_hosts && server->master == NULL) {
        return;
    }

    server->failure_count++;

    log_debug(LOG_VERB, "server '%.*s' failure count %"PRIu32" limit %"PRIu32,
              server->pname.len, server->pname.data, server->failure_count,
              pool->server_failure_limit);

    if (server->failure_count < pool->server_failure_limit) {
        return;
    }

    /* if a slave failed over server_failure_limit, eject it */
    if (server->master != NULL) {
        /* if the server's status is online, we will eject it, log it */
        if (server->status == SERVER_STATUS_ONLINE) {
            /* add a timer to disconnect all the conn after the event loop */
            event_add_timer(ctx, 0, server_disconnect, server, NULL);
            log_warn("eject slave %.*s of %.*s in pool %"PRIu32" '%.*s'", 
                     server->pname.len, server->pname.data,
                     server->name.len, server->name.data,
                     pool->idx, pool->name.len, pool->name.data);
        }

        /* the server status is not disconnected,
         * means the server should reconnect
         */
        if (server->status != SERVER_STATUS_DISCONNECTED) {
            server->status = SERVER_STATUS_DISCONNECTED;
            event_add_timer(ctx, ctx->server_reconnect_interval,
                            server_health_check, server, NULL);
        }
        return;
    }

    now = nc_usec_now();
    if (now < 0) {
        return;
    }
    next = now + pool->server_retry_timeout;

    log_debug(LOG_INFO, "update pool %"PRIu32" '%.*s' to delete server '%.*s' "
              "for next %"PRIu32" secs", pool->idx, pool->name.len,
              pool->name.data, server->pname.len, server->pname.data,
              pool->server_retry_timeout / 1000 / 1000);

    stats_pool_incr(ctx, pool, server_ejects);

    server->failure_count = 0;
    server->next_retry = next;

    status = server_pool_run(pool);
    if (status != NC_OK) {
        log_error("updating pool %"PRIu32" '%.*s' failed: %s", pool->idx,
                  pool->name.len, pool->name.data, strerror(errno));
    }
}

static void
server_close_stats(struct context *ctx, struct server *server, err_t err,
                   unsigned eof, unsigned connected)
{
    if (connected) {
        stats_server_decr(ctx, server, server_connections);
    }

    if (eof) {
        stats_server_incr(ctx, server, server_eof);
        return;
    }

    switch (err) {
    case ETIMEDOUT:
        stats_server_incr(ctx, server, server_timedout);
        break;
    case EPIPE:
    case ECONNRESET:
    case ECONNABORTED:
    case ECONNREFUSED:
    case ENOTCONN:
    case ENETDOWN:
    case ENETUNREACH:
    case EHOSTDOWN:
    case EHOSTUNREACH:
    default:
        stats_server_incr(ctx, server, server_err);
        break;
    }
}

void
server_close(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    struct msg *msg, *nmsg; /* current and next message */
    struct conn *c_conn;    /* peer client connection */

    ASSERT(!conn->client && !conn->proxy);

    server_close_stats(ctx, conn->owner, conn->err, conn->eof,
                       conn->connected);

    if (conn->sd < 0) {
        server_failure(ctx, conn->owner);
        conn->unref(conn);
        conn_put(conn);
        return;
    }

    for (msg = TAILQ_FIRST(&conn->imsg_q); msg != NULL; msg = nmsg) {
        nmsg = TAILQ_NEXT(msg, s_tqe);

        /* dequeue the message (request) from server inq */
        conn->dequeue_inq(ctx, conn, msg);

        /*
         * Don't send any error response, if
         * 1. request is tagged as noreply or,
         * 2. client has already closed its connection
         * all msg in sentinel server's imsg_q are tagged noreply.
         */
        if (msg->swallow || msg->noreply) {
            log_debug(LOG_INFO, "close s %d swallow req %"PRIu64" len %"PRIu32
                      " type %d", conn->sd, msg->id, msg->mlen, msg->type);
            req_put(msg);
        } else {
            c_conn = msg->owner;
            ASSERT(c_conn->client && !c_conn->proxy);

            msg->done = 1;
            msg->error = 1;
            msg->err = conn->err;

            if (req_done(c_conn, TAILQ_FIRST(&c_conn->omsg_q))) {
                event_add_out(ctx->ep, msg->owner);
            }

            log_debug(LOG_INFO, "close s %d schedule error for req %"PRIu64" "
                      "len %"PRIu32" type %d from c %d%c %s", conn->sd, msg->id,
                      msg->mlen, msg->type, c_conn->sd, conn->err ? ':' : ' ',
                      conn->err ? strerror(conn->err): " ");
        }
    }
    ASSERT(TAILQ_EMPTY(&conn->imsg_q));

    /* sentinel server'omsg_q won't have msg for its all req are tagged noreply. */
    for (msg = TAILQ_FIRST(&conn->omsg_q); msg != NULL; msg = nmsg) {
        nmsg = TAILQ_NEXT(msg, s_tqe);

        /* dequeue the message (request) from server outq */
        conn->dequeue_outq(ctx, conn, msg);

        if (msg->swallow) {
            log_debug(LOG_INFO, "close s %d swallow req %"PRIu64" len %"PRIu32
                      " type %d", conn->sd, msg->id, msg->mlen, msg->type);
            req_put(msg);
        } else {
            c_conn = msg->owner;
            ASSERT(c_conn->client && !c_conn->proxy);

            msg->done = 1;
            msg->error = 1;
            msg->err = conn->err;

            if (req_done(c_conn, TAILQ_FIRST(&c_conn->omsg_q))) {
                event_add_out(ctx->ep, msg->owner);
            }

            log_debug(LOG_INFO, "close s %d schedule error for req %"PRIu64" "
                      "len %"PRIu32" type %d from c %d%c %s", conn->sd, msg->id,
                      msg->mlen, msg->type, c_conn->sd, conn->err ? ':' : ' ',
                      conn->err ? strerror(conn->err): " ");
        }
    }
    ASSERT(TAILQ_EMPTY(&conn->omsg_q));

    msg = conn->rmsg;
    if (msg != NULL) {
        conn->rmsg = NULL;

        ASSERT(!msg->request);
        ASSERT(msg->peer == NULL);

        rsp_put(msg);

        log_debug(LOG_INFO, "close s %d discarding rsp %"PRIu64" len %"PRIu32" "
                  "in error", conn->sd, msg->id, msg->mlen);
    }

    ASSERT(conn->smsg == NULL);

    server_failure(ctx, conn->owner);

    conn->unref(conn);

    status = close(conn->sd);
    if (status < 0) {
        log_error("close s %d failed, ignored: %s", conn->sd, strerror(errno));
    }
    conn->sd = -1;

    conn_put(conn);
}

rstatus_t
server_connect(struct context *ctx, struct server *server, struct conn *conn)
{
    rstatus_t status;

    ASSERT(!conn->client && !conn->proxy);

    if (conn->sd > 0) {
        /* already connected on server connection */
        return NC_OK;
    }

    log_debug(LOG_VVERB, "connect to server '%.*s'", server->pname.len,
              server->pname.data);

    conn->sd = socket(conn->family, SOCK_STREAM, 0);
    if (conn->sd < 0) {
        log_error("socket for server '%.*s' failed: %s", server->pname.len,
                  server->pname.data, strerror(errno));
        status = NC_ERROR;
        goto error;
    }

    status = nc_set_nonblocking(conn->sd);
    if (status != NC_OK) {
        log_error("set nonblock on s %d for server '%.*s' failed: %s",
                  conn->sd,  server->pname.len, server->pname.data,
                  strerror(errno));
        goto error;
    }

    if (server->pname.data[0] != '/') {
        status = nc_set_tcpnodelay(conn->sd);
        if (status != NC_OK) {
            log_warn("set tcpnodelay on s %d for server '%.*s' failed, ignored: %s",
                     conn->sd, server->pname.len, server->pname.data,
                     strerror(errno));
        }
    }

    status = event_add_conn(ctx->ep, conn);
    if (status != NC_OK) {
        log_error("event add conn e %d s %d for server '%.*s' failed: %s",
                  ctx->ep, conn->sd, server->pname.len, server->pname.data,
                  strerror(errno));
        goto error;
    }

    ASSERT(!conn->connecting && !conn->connected);

    status = connect(conn->sd, conn->addr, conn->addrlen);
    if (status != NC_OK) {
        if (errno == EINPROGRESS) {
            conn->connecting = 1;
            log_debug(LOG_DEBUG, "connecting on s %d to server '%.*s'",
                      conn->sd, server->pname.len, server->pname.data);
            return NC_OK;
        }

        log_error("connect on s %d to server '%.*s' failed: %s", conn->sd,
                  server->pname.len, server->pname.data, strerror(errno));

        goto error;
    }

    ASSERT(!conn->connecting);
    conn->connected = 1;
    log_debug(LOG_INFO, "connected on s %d to server '%.*s'", conn->sd,
              server->pname.len, server->pname.data);

    return NC_OK;

error:
    conn->err = errno;
    return status;
}

void
server_connected(struct context *ctx, struct conn *conn)
{
    struct server *server = conn->owner;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->connecting && !conn->connected);

    stats_server_incr(ctx, server, server_connections);

    conn->connecting = 0;
    conn->connected = 1;

    log_debug(LOG_INFO, "connected on s %d to server '%.*s'", conn->sd,
              server->pname.len, server->pname.data);
}

void
server_ok(struct context *ctx, struct conn *conn)
{
    struct server *server = conn->owner;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->connected);

    if (server->failure_count != 0) {
        log_debug(LOG_VERB, "reset server '%.*s' failure count from %"PRIu32
                  " to 0", server->pname.len, server->pname.data,
                  server->failure_count);
        server->failure_count = 0;
        server->next_retry = 0LL;
    }
}

static rstatus_t
server_pool_update(struct server_pool *pool)
{
    rstatus_t status;
    int64_t now;
    uint32_t pnlive_server; /* prev # live server */

    if (!pool->auto_eject_hosts) {
        return NC_OK;
    }

    if (pool->next_rebuild == 0LL) {
        return NC_OK;
    }

    now = nc_usec_now();
    if (now < 0) {
        return NC_ERROR;
    }

    if (now <= pool->next_rebuild) {
        if (pool->nlive_server == 0) {
            errno = ECONNREFUSED;
            return NC_ERROR;
        }
        return NC_OK;
    }

    pnlive_server = pool->nlive_server;

    status = server_pool_run(pool);
    if (status != NC_OK) {
        log_error("updating pool %"PRIu32" with dist %d failed: %s", pool->idx,
                  pool->dist_type, strerror(errno));
        return status;
    }

    log_debug(LOG_INFO, "update pool %"PRIu32" '%.*s' to add %"PRIu32" servers",
              pool->idx, pool->name.len, pool->name.data,
              pool->nlive_server - pnlive_server);


    return NC_OK;
}

static rstatus_t
server_set_address(struct server *server, struct string *server_ip, int server_port)
{
    rstatus_t status;
    struct conf_server *conf_server;
    struct sockinfo info;
    char pname_buf[NC_PNAME_MAXLEN];

    status = nc_resolve(server_ip, server_port, &info);
    if (status != NC_OK) {
        log_error("server address %.*s:%d resolve error",
                server_ip->len, server_ip->data, server_port);
        return status;
    }

    /* conf_server's pname and server's pname point to the same data string,
     * so deinit once enough.
     */
    conf_server = server->conf_server;
    string_deinit(&conf_server->pname);

    nc_snprintf(pname_buf, NC_PNAME_MAXLEN, "%.*s:%d:%d",
            server_ip->len, server_ip->data, server_port, server->weight);

    /* update conf_server's pname to used for conf update */
    status = string_copy(&conf_server->pname, pname_buf, (uint32_t)(nc_strlen(pname_buf)));
    if (status != NC_OK) {
        return status;
    }

    /* make server's pname points to conf_server's pname */
    server->pname = conf_server->pname;
    conf_server->port = (uint16_t)server_port;
    server->port = (uint16_t)server_port;
    ASSERT(server->family == info.family);
    ASSERT(server->addrlen == info.addrlen);
    /* server'addr is a pointer to conf_server->info->addr,
     * so update conf_server'info can update server's addr
     */
    conf_server->info = info;

    return NC_OK;
}

rstatus_t
server_switch(struct context *ctx, struct string *pool_name,
        struct string *server_name, struct string *server_ip, int server_port)
{
    rstatus_t status;
    struct server_pool *server_pool;
    struct server *server, *slave_server;
    struct string pname;
    char pname_buf[NC_PNAME_MAXLEN];
    uint32_t i;

    /* find same name server pool */
    server_pool = NULL;
    for(i = 0; i < array_n(&ctx->pool); i++) {
        server_pool = array_get(&ctx->pool, i);
        if (!string_compare(&server_pool->name, pool_name)) {
            break;
        }
        server_pool = NULL;
    }
    if (server_pool == NULL) {
        log_warn("server switch don't find pool %.*s",
                pool_name->len, pool_name->data);
        return NC_ERROR;
    }

    /* find same name server */
    server = NULL;
    for(i = 0; i < array_n(&server_pool->server); i++) {
        server = array_get(&server_pool->server, i);
        if (!string_compare(&server->name, server_name)) {
            break;
        }
        server = NULL;
    }
    if (server == NULL) {
        log_warn("server switch don't find %.*s in %.*s",
                server_name->len, server_name->data,
                pool_name->len, pool_name->data);
        return NC_ERROR;
    }

    string_init(&pname);
    nc_snprintf(pname_buf, NC_PNAME_MAXLEN, "%.*s:%d:%d",
            server_ip->len, server_ip->data, server_port, server->weight);
    status = string_copy(&pname, pname_buf, (uint32_t)(nc_strlen(pname_buf)));
    if (status != NC_OK) {
        return status;
    }
    if (!string_compare(&server->pname, &pname)) {
        log_warn("%.*s-%.*s have same address %.*s:%d",
                pool_name->len, pool_name->data,
                server_name->len, server_name->data,
                server_ip->len, server_ip->data, server_port);
        string_deinit(&pname);
        return NC_ERROR;
    }
    /* pname is no longer used, release it */
    string_deinit(&pname);

    /* if we have slave with addr same as master, change its address.
     * we just change its address, if the slave is not online, the reconnect
     * timer will make online again, so we don't need to change its status.
     */
    for (i = 0; i < array_n(&server->slave); i++) {
        slave_server = array_get(&server->slave, i);
        if (!server_address_compare(slave_server, server)) {
            status = server_set_address(slave_server, server_ip, server_port);
            if (status != NC_OK) {
                return status;
            }
        }
    }

    /* change the master's address */
    status = server_set_address(server, server_ip, server_port);
    if (status != NC_OK) {
        return status;
    }

    /* disconnect all the connection include the slaves's.
     * use the timer to disconnect after the file event loop.
     */
    event_add_timer(ctx, 0, server_disconnect, server, NULL);

    log_warn("success switch %.*s-%.*s to %.*s",
            pool_name->len, pool_name->data,
            server_name->len, server_name->data,
            server->pname.len, server->pname.data);

    return NC_OK;
}

static uint32_t
server_pool_hash(struct server_pool *pool, uint8_t *key, uint32_t keylen)
{
    ASSERT(array_n(&pool->server) != 0);

    if (array_n(&pool->server) == 1) {
        return 0;
    }

    ASSERT(key != NULL && keylen != 0);

    return pool->key_hash((char *)key, keylen);
}

static struct server *
server_pool_server(struct server_pool *pool, uint8_t *key, uint32_t keylen)
{
    struct server *server;
    uint32_t hash, idx;

    ASSERT(array_n(&pool->server) != 0);
    ASSERT(key != NULL && keylen != 0);

    switch (pool->dist_type) {
    case DIST_KETAMA:
        hash = server_pool_hash(pool, key, keylen);
        idx = ketama_dispatch(pool->continuum, pool->ncontinuum, hash);
        break;

    case DIST_MODULA:
        hash = server_pool_hash(pool, key, keylen);
        idx = modula_dispatch(pool->continuum, pool->ncontinuum, hash);
        break;
        
    case DIST_SLOT:
        hash = server_pool_hash(pool, key, keylen);
        idx = slot_dispatch(pool->continuum, pool->ncontinuum, hash);
        break;

    case DIST_RANDOM:
        idx = random_dispatch(pool->continuum, pool->ncontinuum, 0);
        break;

    default:
        NOT_REACHED();
        return NULL;
    }
    ASSERT(idx < array_n(&pool->server));

    server = array_get(&pool->server, idx);

    log_debug(LOG_VERB, "key '%.*s' on dist %d maps to server '%.*s'", keylen,
              key, pool->dist_type, server->name.len, server->name.data);

    return server;
}

static struct server *
server_rwsplit_pick(struct server *server, msg_type_t type)
{
    struct server *server_select;
    uint32_t i, slave_index, nslave;

    ASSERT(server->master == NULL);

    nslave = array_n(&server->slave);

    /* if the request is write or no slave configed, return master */
    if (type & PERM_W || nslave == 0) {
        return server;
    }

    /* Round-Robin select slave whose status is online */
    slave_index = server->slave_select;
    for (i = 0; i < nslave; i++) {
        slave_index = slave_index < nslave - 1 ? slave_index + 1 : 0;
        server_select = array_get(&server->slave, slave_index);
        if (server_select->status == SERVER_STATUS_ONLINE) {
            server->slave_select = slave_index;
            return server_select;
        }
    }

    return server;
}

struct conn *
server_pool_conn(struct context *ctx, struct server_pool *pool, uint8_t *key,
                 uint32_t keylen, msg_type_t type)
{
    rstatus_t status;
    struct server *server;
    struct conn *conn;

    status = server_pool_update(pool);
    if (status != NC_OK) {
        return NULL;
    }

    /* from a given {key, keylen} pick a master server from pool */
    server = server_pool_server(pool, key, keylen);
    if (server == NULL) {
        return NULL;
    }

    /* pick a server based on the request type(read or write) */
    server = server_rwsplit_pick(server, type);
    log_debug(LOG_VERB, "key '%.*s' of request %d on dist %d rwsplit to '%.*s'",
              keylen, key, type, pool->dist_type, server->pname.len, server->pname.data);

    /* pick a connection to a given server */
    conn = server_conn(server);
    if (conn == NULL) {
        return NULL;
    }

    status = server_connect(ctx, server, conn);
    if (status != NC_OK) {
        server_close(ctx, conn);
        return NULL;
    }

    return conn;
}

static rstatus_t
server_pool_each_preconnect(void *elem, void *data)
{
    rstatus_t status;
    struct server_pool *sp = elem;

    if (!sp->preconnect) {
        return NC_OK;
    }

    status = array_each(&sp->server, server_each_preconnect, NULL);
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}

rstatus_t
server_pool_preconnect(struct context *ctx)
{
    rstatus_t status;

    status = array_each(&ctx->pool, server_pool_each_preconnect, NULL);
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}

static rstatus_t
server_pool_each_disconnect(void *elem, void *data)
{
    rstatus_t status;
    struct server_pool *sp = elem;

    status = array_each(&sp->server, server_each_disconnect, NULL);
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}

void
server_pool_disconnect(struct context *ctx)
{
    array_each(&ctx->pool, server_pool_each_disconnect, NULL);
}

static rstatus_t
server_pool_each_set_owner(void *elem, void *data)
{
    struct server_pool *sp = elem;
    struct context *ctx = data;

    sp->ctx = ctx;

    return NC_OK;
}

rstatus_t
server_pool_run(struct server_pool *pool)
{
    ASSERT(array_n(&pool->server) != 0);

    switch (pool->dist_type) {
    case DIST_KETAMA:
        return ketama_update(pool);

    case DIST_MODULA:
        return modula_update(pool);
        
    case DIST_SLOT:
        return slot_update(pool);
        
    case DIST_RANDOM:
        return random_update(pool);

    default:
        NOT_REACHED();
        return NC_ERROR;
    }

    return NC_OK;
}

static rstatus_t
server_pool_each_run(void *elem, void *data)
{
    return server_pool_run(elem);
}

rstatus_t
server_pool_init(struct array *server_pool, struct array *conf_pool,
                 struct context *ctx)
{
    rstatus_t status;
    uint32_t npool;

    npool = array_n(conf_pool);
    ASSERT(npool != 0);
    ASSERT(array_n(server_pool) == 0);

    status = array_init(server_pool, npool, sizeof(struct server_pool));
    if (status != NC_OK) {
        return status;
    }

    /* transform conf pool to server pool */
    status = array_each(conf_pool, conf_pool_each_transform, server_pool);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }
    ASSERT(array_n(server_pool) == npool);

    /* set ctx as the server pool owner */
    status = array_each(server_pool, server_pool_each_set_owner, ctx);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }

    /* update server pool continuum */
    status = array_each(server_pool, server_pool_each_run, NULL);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }

    log_debug(LOG_DEBUG, "init %"PRIu32" pools", npool);

    return NC_OK;
}

void
server_pool_deinit(struct array *server_pool)
{
    uint32_t i, npool;

    for (i = 0, npool = array_n(server_pool); i < npool; i++) {
        struct server_pool *sp;

        sp = array_pop(server_pool);
        ASSERT(sp->p_conn == NULL);
        ASSERT(TAILQ_EMPTY(&sp->c_conn_q) && sp->nc_conn_q == 0);

        if (sp->continuum != NULL) {
            nc_free(sp->continuum);
            sp->ncontinuum = 0;
            sp->nserver_continuum = 0;
            sp->nlive_server = 0;
        }

        server_deinit(&sp->server);

        log_debug(LOG_DEBUG, "deinit pool %"PRIu32" '%.*s'", sp->idx,
                  sp->name.len, sp->name.data);
    }

    array_deinit(server_pool);

    log_debug(LOG_DEBUG, "deinit %"PRIu32" pools", npool);
}
