#ifndef _NC_SENTINEL_H_
#define _NC_SENTINEL_H_

#include <nc_core.h>

#define SENTINEL_ADDR             "127.0.0.1"
#define SENTINEL_PORT             26379

#define SENTINEL_SERVERNAME_SPLIT '-'

typedef enum sentinel_conn_status {
    SENTINEL_CONN_DISCONNECTED,
    SENTINEL_CONN_SEND_REQ,
    SENTINEL_CONN_ACK_INFO,
    SENTINEL_CONN_ACK_SUB,
} sentinel_conn_status_t;

struct conn * sentinel_conn(struct server *sentinel);
struct conn * sentinel_connect(struct context *ctx);
struct server * sentinel_init(uint16_t sentinel_port, char *sentinel_ip);
void sentinel_deinit(struct server *sentinel);
void sentinel_recv_done(struct context *ctx, struct conn *conn, struct msg *msg, struct msg *nmsg);
void sentinel_close(struct context *ctx, struct conn *conn);
int sentinel_reconnect(struct context *ctx, long long id, void *client_data);

#endif
