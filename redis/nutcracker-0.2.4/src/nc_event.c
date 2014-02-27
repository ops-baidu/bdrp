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

#include <unistd.h>
#include <sys/epoll.h>
#include <sys/time.h>

#include <nc_core.h>

int
event_init(struct context *ctx, int size)
{
    int status, ep;
    struct epoll_event *event;

    ASSERT(ctx->ep < 0);
    ASSERT(ctx->nevent != 0);
    ASSERT(ctx->event == NULL);

    ep = epoll_create(size);
    if (ep < 0) {
        log_error("epoll create of size %d failed: %s", size, strerror(errno));
        return -1;
    }

    event = nc_calloc(ctx->nevent, sizeof(*ctx->event));
    if (event == NULL) {
        status = close(ep);
        if (status < 0) {
            log_error("close e %d failed, ignored: %s", ep, strerror(errno));
        }
        return -1;
    }

    ctx->ep = ep;
    ctx->event = event;

    ctx->last_time = time(NULL);
    ctx->time_event_head = NULL;
    ctx->time_event_next_id = 0;

    log_debug(LOG_INFO, "e %d with nevent %d timeout %d", ctx->ep,
              ctx->nevent, ctx->timeout);

    return 0;
}

void
event_deinit(struct context *ctx)
{
    int status;

    ASSERT(ctx->ep >= 0);

    nc_free(ctx->event);

    status = close(ctx->ep);
    if (status < 0) {
        log_error("close e %d failed, ignored: %s", ctx->ep, strerror(errno));
    }
    ctx->ep = -1;
}

int
event_add_out(int ep, struct conn *c)
{
    int status;
    struct epoll_event event;

    ASSERT(ep > 0);
    ASSERT(c != NULL);
    ASSERT(c->sd > 0);
    ASSERT(c->recv_active);

    if (c->send_active) {
        return 0;
    }

    event.events = (uint32_t)(EPOLLIN | EPOLLOUT | EPOLLET);
    event.data.ptr = c;

    status = epoll_ctl(ep, EPOLL_CTL_MOD, c->sd, &event);
    if (status < 0) {
        log_error("epoll ctl on e %d sd %d failed: %s", ep, c->sd,
                  strerror(errno));
    } else {
        c->send_active = 1;
    }

    return status;
}

int
event_del_out(int ep, struct conn *c)
{
    int status;
    struct epoll_event event;

    ASSERT(ep > 0);
    ASSERT(c != NULL);
    ASSERT(c->sd > 0);
    ASSERT(c->recv_active);

    if (!c->send_active) {
        return 0;
    }

    event.events = (uint32_t)(EPOLLIN | EPOLLET);
    event.data.ptr = c;

    status = epoll_ctl(ep, EPOLL_CTL_MOD, c->sd, &event);
    if (status < 0) {
        log_error("epoll ctl on e %d sd %d failed: %s", ep, c->sd,
                  strerror(errno));
    } else {
        c->send_active = 0;
    }

    return status;
}

int
event_add_conn(int ep, struct conn *c)
{
    int status;
    struct epoll_event event;

    ASSERT(ep > 0);
    ASSERT(c != NULL);
    ASSERT(c->sd > 0);

    event.events = (uint32_t)(EPOLLIN | EPOLLOUT | EPOLLET);
    event.data.ptr = c;

    status = epoll_ctl(ep, EPOLL_CTL_ADD, c->sd, &event);
    if (status < 0) {
        log_error("epoll ctl on e %d sd %d failed: %s", ep, c->sd,
                  strerror(errno));
    } else {
        c->send_active = 1;
        c->recv_active = 1;
    }

    return status;
}

int
event_del_conn(int ep, struct conn *c)
{
    int status;

    ASSERT(ep > 0);
    ASSERT(c != NULL);
    ASSERT(c->sd > 0);

    status = epoll_ctl(ep, EPOLL_CTL_DEL, c->sd, NULL);
    if (status < 0) {
        log_error("epoll ctl on e %d sd %d failed: %s", ep, c->sd,
                  strerror(errno));
    } else {
        c->recv_active = 0;
        c->send_active = 0;
    }

    return status;
}

int
event_wait(int ep, struct epoll_event *event, int nevent, int timeout)
{
    int nsd;

    ASSERT(ep > 0);
    ASSERT(event != NULL);
    ASSERT(nevent > 0);

    for (;;) {
        nsd = epoll_wait(ep, event, nevent, timeout);
        if (nsd > 0) {
            return nsd;
        }

        if (nsd == 0) {
            if (timeout == -1) {
               log_error("epoll wait on e %d with %d events and %d timeout "
                         "returned no events", ep, nevent, timeout);
                return -1;
            }

            return 0;
        }

        if (errno == EINTR) {
            continue;
        }

        log_error("epoll wait on e %d with %d events failed: %s", ep, nevent,
                  strerror(errno));

        return -1;
    }

    NOT_REACHED();
}

void
event_get_time(long *seconds, long *milliseconds)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    *seconds = tv.tv_sec;
    *milliseconds = tv.tv_usec/1000;
}

static void
event_add_milliseconds_to_now(long long milliseconds, long *sec, long *ms) {
    long cur_sec, cur_ms, when_sec, when_ms;

    event_get_time(&cur_sec, &cur_ms);
    when_sec = cur_sec + milliseconds/1000;
    when_ms = cur_ms + milliseconds%1000;
    if (when_ms >= 1000) {
        when_sec ++;
        when_ms -= 1000;
    }
    *sec = when_sec;
    *ms = when_ms;
}

long long
event_add_timer(struct context *ctx, long long milliseconds,
        aeTimeProc *proc, void *clientData,
        aeEventFinalizerProc *finalizerProc)
{
    long long id = ctx->time_event_next_id++;
    struct time_event *te;

    te = nc_alloc(sizeof(*te));
    if (te == NULL) return NC_ERROR;
    te->id = id;
    event_add_milliseconds_to_now(milliseconds,&te->when_sec,&te->when_ms);
    te->timeProc = proc;
    te->finalizerProc = finalizerProc;
    te->clientData = clientData;
    te->next = ctx->time_event_head;
    ctx->time_event_head = te;
    return id;
}

int
event_delete_timer(struct context *ctx, long long id)
{
    struct time_event *te, *prev = NULL;

    te = ctx->time_event_head;
    while(te) {
        if (te->id == id) {
            if (prev == NULL)
                ctx->time_event_head = te->next;
            else
                prev->next = te->next;
            if (te->finalizerProc)
                te->finalizerProc(ctx, te->clientData);
            nc_free(te);
            return NC_OK;
        }
        prev = te;
        te = te->next;
    }
    return NC_ERROR; /* NO event with the specified ID found */
}

/* Search the first timer to fire.
 * This operation is useful to know how many time the select can be
 * put in sleep without to delay any event.
 * If there are no timers NULL is returned.
 *
 * Note that's O(N) since time events are unsorted.
 * Possible optimizations (not needed by Redis so far, but...):
 * 1) Insert the event in order, so that the nearest is just the head.
 *    Much better but still insertion or deletion of timers is O(N).
 * 2) Use a skiplist to have this operation as O(1) and insertion as O(log(N)).
 */
struct time_event *
event_search_nearest_timer(struct context *ctx)
{
    struct time_event *te = ctx->time_event_head;
    struct time_event *nearest = NULL;

    while(te) {
        if (!nearest || te->when_sec < nearest->when_sec ||
                (te->when_sec == nearest->when_sec &&
                 te->when_ms < nearest->when_ms))
            nearest = te;
        te = te->next;
    }
    return nearest;
}

/* Process time events */
int
event_process_timer(struct context *ctx) {
    int processed = 0;
    struct time_event *te;
    long long maxId;
    time_t now = time(NULL);

    /* If the system clock is moved to the future, and then set back to the
     * right value, time events may be delayed in a random way. Often this
     * means that scheduled operations will not be performed soon enough.
     *
     * Here we try to detect system clock skews, and force all the time
     * events to be processed ASAP when this happens: the idea is that
     * processing events earlier is less dangerous than delaying them
     * indefinitely, and practice suggests it is. */
    if (now < ctx->last_time) {
        te = ctx->time_event_head;
        while(te) {
            te->when_sec = 0;
            te = te->next;
        }
    }
    ctx->last_time = now;

    te = ctx->time_event_head;
    maxId = ctx->time_event_next_id-1;
    while(te) {
        long now_sec, now_ms;
        long long id;

        if (te->id > maxId) {
            te = te->next;
            continue;
        }
        event_get_time(&now_sec, &now_ms);
        if (now_sec > te->when_sec ||
            (now_sec == te->when_sec && now_ms >= te->when_ms))
        {
            int retval;

            id = te->id;
            retval = te->timeProc(ctx, id, te->clientData);
            processed++;
            /* After an event is processed our time event list may
             * no longer be the same, so we restart from head.
             * Still we make sure to don't process events registered
             * by event handlers itself in order to don't loop forever.
             * To do so we saved the max ID we want to handle.
             *
             * FUTURE OPTIMIZATIONS:
             * Note that this is NOT great algorithmically. Redis uses
             * a single time event so it's not a problem but the right
             * way to do this is to add the new elements on head, and
             * to flag deleted elements in a special way for later
             * deletion (putting references to the nodes to delete into
             * another linked list). */
            if (retval != EVENT_TIMER_NOMORE) {
                event_add_milliseconds_to_now(retval,&te->when_sec,&te->when_ms);
            } else {
                event_delete_timer(ctx, id);
            }
            te = ctx->time_event_head;
        } else {
            te = te->next;
        }
    }
    return processed;
}
