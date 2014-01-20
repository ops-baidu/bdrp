#include <nc_sentinel.h>
#include <nc_server.h>
#include <nc_connection.h>
#include <nc_core.h>
#include <nc_event.h>
#include <nc_conf.h>

static char *sentinel_req_cmds[] = {
    MSG_INFO_SENTINEL_STRING,
    MSG_SUB_SWITCH_STRING
};

static sentinel_conn_status_t sentinel_status;

struct conn *
sentinel_conn(struct server *sentinel)
{
    struct conn *conn;

    /* sentinel has only one connection */
    if (sentinel->ns_conn_q == 0) {
        return conn_get_sentinel(sentinel);
    }
    ASSERT(sentinel->ns_conn_q == 1);

    conn = TAILQ_FIRST(&sentinel->s_conn_q);
    ASSERT(!conn->client && !conn->proxy);

    return conn;
}

struct conn *
sentinel_connect(struct context *ctx)
{
    rstatus_t status;
    struct conn *conn;
    int cmd_num;
    int i;

    ASSERT(sentinel_status == SENTINEL_CONN_DISCONNECTED);

    /* get the only connect of sentinel */
    conn = sentinel_conn(ctx->sentinel);
    if (conn == NULL) {
        return NULL;
    }

    status = server_connect(ctx, ctx->sentinel, conn);
    if(status != NC_OK) {
        sentinel_close(ctx, conn);
        return NULL;
    }

    cmd_num = sizeof(sentinel_req_cmds) / sizeof(char *);
    for (i = 0; i < cmd_num; i++) {
        status = req_construct(ctx, conn, sentinel_req_cmds[i]);
        if(status != NC_OK) {
            sentinel_close(ctx, conn);
            return NULL;
        }
    }

    sentinel_status = SENTINEL_CONN_SEND_REQ;

    return conn;
}


struct server *
sentinel_init(uint16_t sentinel_port, char *sentinel_ip)
{
    rstatus_t status;
    struct server *sentinel;
    struct string address;
    struct sockinfo info;
    char pname[NC_PNAME_MAXLEN];

    string_init(&address);

    sentinel_status = SENTINEL_CONN_DISCONNECTED;

    sentinel = (struct server *)nc_alloc(sizeof(*sentinel));
    if(sentinel == NULL) {
        goto error;
    }

    /* sentinel server don't have owner server pool */
    sentinel->owner = NULL;
    sentinel->ns_conn_q = 0;
    TAILQ_INIT(&sentinel->s_conn_q);
    sentinel->addr = NULL;
    string_init(&sentinel->pname);
    string_init(&sentinel->name);

    nc_snprintf(pname, NC_PNAME_MAXLEN, "%s:%d:0", sentinel_ip, sentinel_port);
    status = string_copy(&sentinel->pname, pname, (uint32_t)(nc_strlen(pname)));
    if (status != NC_OK) {
        goto error;
    }

    string_copy(&sentinel->name, pname, (uint32_t)(nc_strlen(pname)) - 2);
    if (status != NC_OK) {
        goto error;
    }

    sentinel->port = sentinel_port;

    status = string_copy(&address, sentinel_ip, (uint32_t)(nc_strlen(sentinel_ip)));
    if (status != NC_OK) {
        goto error;
    }

    status = nc_resolve(&address, sentinel_port, &info);
    if (status != NC_OK) {
        goto error;
    }

    sentinel->family = info.family;
    sentinel->addrlen = info.addrlen;
    sentinel->addr = (struct sockaddr*)nc_alloc(info.addrlen);
    if (sentinel->addr == NULL) {
        goto error;
    }
    nc_memcpy(sentinel->addr, &info.addr, info.addrlen);

done:
    string_deinit(&address);
    return sentinel;

error:
    sentinel_deinit(sentinel);
    sentinel = NULL;
    goto done;
}

void
sentinel_deinit(struct server *sentinel)
{
    if (sentinel == NULL) {
        return;
    }

    ASSERT(TAILQ_EMPTY(&sentinel->s_conn_q) && sentinel->ns_conn_q == 0);

    string_deinit(&sentinel->name);
    string_deinit(&sentinel->pname);
    if (sentinel->addr != NULL) {
        nc_free(sentinel->addr);
    }
    nc_free(sentinel);
}

void
sentinel_close(struct context *ctx, struct conn *conn)
{
    server_close(ctx, conn);
    sentinel_status = SENTINEL_CONN_DISCONNECTED;

    event_add_timer(ctx, ctx->server_reconnect_interval, sentinel_reconnect, NULL, NULL);
}

int
sentinel_reconnect(struct context *ctx, long long id, void *client_data)
{
    ASSERT(sentinel_status == SENTINEL_CONN_DISCONNECTED);
    sentinel_connect(ctx);

    return EVENT_TIMER_NOMORE;
}

static rstatus_t
sentinel_proc_sentinel_info(struct context *ctx, struct msg *msg)
{
    rstatus_t status;
    int i, master_num, switch_num;
    struct string pool_name, server_name, server_ip,
                  tmp_string, sentinel_masters_prefix, master_ok;
    struct mbuf *line_buf;
    int server_port;

    string_init(&tmp_string);
    string_init(&pool_name);
    string_init(&server_name);
    string_init(&server_ip);
    string_set_text(&sentinel_masters_prefix, "sentinel_masters");
    string_set_text(&master_ok, "status=ok");

    line_buf = mbuf_get();
    if (line_buf == NULL) {
        goto error;
    }

    /* get sentinel master num at line 3 */
    msg_read_line(msg, line_buf, 3);
    if (mbuf_length(line_buf) == 0) {
        log_error("read line failed from sentinel ack info when skip line not used.");
        goto error;
    }
    status = mbuf_read_string(line_buf, ':', &tmp_string);
    if (status != NC_OK || string_compare(&sentinel_masters_prefix, &tmp_string)) {
        goto error;
    }
    status = mbuf_read_string(line_buf, CR, &tmp_string);
    if (status != NC_OK) {
        goto error;
    }
    master_num = nc_atoi(tmp_string.data, tmp_string.len);
    if (master_num < 0) {
        log_error("parse master number from sentinel ack info failed.");
        goto error;
    }

    /* skip 3 line in ack info which is not used. */
    msg_read_line(msg, line_buf, 3);
    if (mbuf_length(line_buf) == 0) {
        log_error("read line failed from sentinel ack info when skip line not used.");
        goto error;
    }

    /* parse master info from sentinel ack info */
    switch_num = 0;
    for (i = 0; i < master_num; i++) {
        msg_read_line(msg, line_buf, 1);
        if (mbuf_length(line_buf) == 0) {
            log_error("read line failed from sentinel ack info when parse master item.");
            goto error;
        }
        log_debug(LOG_INFO, "master item line : %.*s", mbuf_length(line_buf), line_buf->pos);

        /* skip master item prefix */
        status = mbuf_read_string(line_buf, ':', NULL);
        if (status != NC_OK) {
            log_error("skip master item prefix failed");
            goto error;
        }

        /* skip master item server name prefix */
        status = mbuf_read_string(line_buf, '=', NULL);
        if (status != NC_OK) {
            log_error("skip master item server name prefix failed.");
            goto error;
        }

        /* get server pool name */
        status = mbuf_read_string(line_buf, SENTINEL_SERVERNAME_SPLIT, &pool_name);
        if (status != NC_OK) {
            log_error("get server pool name failed.");
            goto error;
        }

        /* get server name */
        status = mbuf_read_string(line_buf, ',', &server_name);
        if (status != NC_OK) {
            log_error("get server name failed.");
            goto error;
        }

        /* get master status */
        status = mbuf_read_string(line_buf, ',', &tmp_string);
        if (status != NC_OK) {
            log_error("get master status failed.");
            goto error;
        }
        if (string_compare(&master_ok, &tmp_string)) { 
            log_error("master item status is not ok, use it anyway");
        }

        /* skip ip string prefix name */
        status = mbuf_read_string(line_buf, '=', NULL);
        if (status != NC_OK) {
            log_error("skip master item address prefix failed.");
            goto error;
        }

        /* get server ip string */
        status = mbuf_read_string(line_buf, ':', &server_ip);
        if (status != NC_OK) {
            log_error("get server ip string failed.");
            goto error;
        }

        /* get server port */
        status = mbuf_read_string(line_buf, ',', &tmp_string);
        if (status != NC_OK) {
            log_error("get server port string failed.");
            goto error;
        }
        server_port = nc_atoi(tmp_string.data, tmp_string.len);
        if (server_port < 0) {
            log_error("tanslate server port string to int failed.");
            goto error;
        }

        status = server_switch(ctx, &pool_name, &server_name, &server_ip, server_port);
        /* if server is switched, add switch number */
        if (status == NC_OK) {
            switch_num++;
        }
    }

    if (switch_num > 0) {
        conf_rewrite(ctx);
    }

    status = NC_OK;

done:
    if (line_buf != NULL) {
        mbuf_put(line_buf);
    }
    string_deinit(&tmp_string);
    string_deinit(&pool_name);
    string_deinit(&server_name);
    string_deinit(&server_ip);
    return status;

error:
    status = NC_ERROR;
    goto done;
}

static rstatus_t
sentinel_proc_acksub(struct context *ctx, struct msg *msg)
{
    rstatus_t status;
    struct string sub_titile, sub_channel, sub_ok, tmp_string;
    struct mbuf *line_buf;

    string_init(&tmp_string);
    string_set_text(&sub_titile, "psubscribe");
    string_set_text(&sub_channel, "+switch-master");
    string_set_text(&sub_ok, ":1");

    line_buf = mbuf_get();
    if (line_buf == NULL) {
        goto error;
    }

    /* get line in line num 3  for sub titile */
    msg_read_line(msg, line_buf, 3);
    if (mbuf_length(line_buf) == 0) {
        log_error("read line failed from sentinel ack sub when skip line not used.");
        goto error;
    }
    status = mbuf_read_string(line_buf, CR, &tmp_string);
    if (status != NC_OK || string_compare(&sub_titile, &tmp_string)) {
        goto error;
    }

    /* get line in line num 5  for sub channel */
    msg_read_line(msg, line_buf, 2);
    if (mbuf_length(line_buf) == 0) {
        log_error("read line failed from sentinel ack sub when skip line not used.");
        goto error;
    }
    status = mbuf_read_string(line_buf, CR, &tmp_string);
    if (status != NC_OK || string_compare(&sub_channel, &tmp_string)) {
        goto error;
    }

    /* get sub status */
    msg_read_line(msg, line_buf, 1);
    if (line_buf == 0) {
        log_error("read line failed from sentinel ack sub when skip line not used.");
        goto error;
    }
    status = mbuf_read_string(line_buf, CR, &tmp_string);
    if (status != NC_OK || string_compare(&sub_ok, &tmp_string)) {
        goto error;
    }

    log_debug(LOG_INFO, "success sub channel %.*s from sentinel", sub_channel.len, sub_channel.data);

    status = NC_OK;

done:
    if (line_buf != NULL) {
        mbuf_put(line_buf);
    }
    string_deinit(&tmp_string);
    return status;

error:
    status = NC_ERROR;
    goto done;
}

static rstatus_t
sentinel_proc_pub(struct context *ctx, struct msg *msg)
{
    rstatus_t status;
    struct string pool_name, server_name, server_ip,
                  tmp_string, pub_titile, pub_event;
    struct mbuf *line_buf;
    int server_port;

    string_init(&tmp_string);
    string_init(&pool_name);
    string_init(&server_name);
    string_init(&server_ip);

    string_set_text(&pub_titile, "pmessage");
    string_set_text(&pub_event, "+switch-master");

    line_buf = mbuf_get();
    if (line_buf == NULL) {
        goto error;
    }

    /* get line in line num 3  for pub titile */
    msg_read_line(msg, line_buf, 3);
    if (mbuf_length(line_buf) == 0) {
        log_error("read line failed from sentinel pmessage when skip line not used.");
        goto error;
    }
    status = mbuf_read_string(line_buf, CR, &tmp_string);
    if (status != NC_OK || string_compare(&pub_titile, &tmp_string)) {
        log_error("pub title error(lineinfo %.*s)", tmp_string.len, tmp_string.data);
        goto error;
    }

    /* get line in line num 7  for pub event */
    msg_read_line(msg, line_buf, 4);
    if (mbuf_length(line_buf) == 0) {
        log_error("read line failed from sentinel pmessage when skip line not used.");
        goto error;
    }
    status = mbuf_read_string(line_buf, CR, &tmp_string);
    if (status != NC_OK || string_compare(&pub_event, &tmp_string)) {
        log_error("pub channel error(lineinfo %.*s)", tmp_string.len, tmp_string.data);
        goto error;
    }

    /* get line in line num 9 for pub info */
    msg_read_line(msg, line_buf, 2);
    if (mbuf_length(line_buf) == 0) {
        log_error("read line failed from sentinel pmessage when skip line not used.");
        goto error;
    }

    /* parse switch master info */
    /* get pool name */
    status = mbuf_read_string(line_buf, SENTINEL_SERVERNAME_SPLIT, &pool_name);
    if (status != NC_OK) {
        log_error("get pool name string failed.");
        goto error;
    }

    /* get server name */
    status = mbuf_read_string(line_buf, ' ', &server_name);
    if (status != NC_OK) {
        log_error("get server name string failed.");
        goto error;
    }

    /* skip old ip and port string */
    status = mbuf_read_string(line_buf, ' ', NULL);
    if (status != NC_OK) {
        log_error("skip old ip string failed.");
        goto error;
    }
    status = mbuf_read_string(line_buf, ' ', NULL);
    if (status != NC_OK) {
        log_error("skip old port string failed.");
        goto error;
    }

    /* get new server ip string */
    status = mbuf_read_string(line_buf, ' ', &server_ip);
    if (status != NC_OK) {
        log_error("get new server ip string failed.");
        goto error;
    }

    /* get new server port */
    status = mbuf_read_string(line_buf, CR, &tmp_string);
    if (status != NC_OK) {
        log_error("get new server port string failed.");
        goto error;
    }
    server_port = nc_atoi(tmp_string.data, tmp_string.len);
    if (server_port < 0) {
        log_error("tanslate server port string to int failed.");
        goto error;
    }

    status = server_switch(ctx, &pool_name, &server_name, &server_ip, server_port);
    if (status == NC_OK) {
        conf_rewrite(ctx);
    }

    status = NC_OK;

done:
    if (line_buf != NULL) {
        mbuf_put(line_buf);
    }
    string_deinit(&tmp_string);
    string_deinit(&server_ip);
    string_deinit(&server_name);
    string_deinit(&pool_name);
    return status;

error:
    status = NC_ERROR;
    goto done;
}

void
sentinel_recv_done(struct context *ctx, struct conn *conn, struct msg *msg,
              struct msg *nmsg)
{
    rstatus_t status;

    ASSERT(!conn->client && !conn->proxy && conn->sentinel);
    ASSERT(msg != NULL && conn->rmsg == msg);
    ASSERT(!msg->request);
    ASSERT(msg->owner == conn);
    ASSERT(nmsg == NULL || !nmsg->request);
    ASSERT(sentinel_status != SENTINEL_CONN_DISCONNECTED);

    /* enqueue next message (response), if any */
    conn->rmsg = nmsg;

    switch (sentinel_status) {
    case SENTINEL_CONN_SEND_REQ:
        status = sentinel_proc_sentinel_info(ctx, msg);
        if (status == NC_OK) {
            sentinel_status = SENTINEL_CONN_ACK_INFO;
        }
        break;

    case SENTINEL_CONN_ACK_INFO:
        status = sentinel_proc_acksub(ctx, msg);
        if (status == NC_OK) {
            sentinel_status = SENTINEL_CONN_ACK_SUB;
        }
        break;

    case SENTINEL_CONN_ACK_SUB:
        status = sentinel_proc_pub(ctx, msg);
        break;

    default:
        status = NC_ERROR;
    }

    rsp_put(msg);
    
    if (status != NC_OK) {
        log_error("sentinel's response error, close sentinel conn.");
        conn->done = 1;
    }
}
