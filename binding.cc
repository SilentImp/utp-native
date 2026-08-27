#include <node_api.h>
#include <napi-macros.h>
#include <uv.h>
#include <stdlib.h>
#include <string.h>
#include "./deps/libutp/utp.h"

#define UTP_NAPI_TIMEOUT_INTERVAL 20

// Room for the longest address text this module can meet. It used to be 17,
// which is the IPv4 maximum, and that single number is what made every address
// path here IPv4-only: an IPv6 literal did not fit, so it was never accepted.
#define UTP_NAPI_IP_MAX 46

// How much of a sockaddr is meaningful. libutp is handed this, and passing
// sizeof(struct sockaddr) — as this module did — describes an IPv4 address and
// truncates an IPv6 one.
static inline size_t
utp_napi_addr_len (const struct sockaddr *addr) {
  return addr->sa_family == AF_INET6
    ? sizeof(struct sockaddr_in6)
    : sizeof(struct sockaddr_in);
}

// Text plus port to an address of whichever family the text names.
static inline int
utp_napi_addr_from_text (const char *ip, int port, struct sockaddr_storage *out) {
  if (uv_ip4_addr(ip, port, (struct sockaddr_in *) out) == 0) return 0;
  return uv_ip6_addr(ip, port, (struct sockaddr_in6 *) out);
}

// A dual-stack socket -- one bound to :: -- carries IPv4 peers as v4-mapped
// addresses, and that mapping has to run in BOTH directions. The kernel does it
// for arriving datagrams, which is why utp_napi_parse_address unmaps on the way
// out; nothing does it for a datagram being sent, so an IPv4 destination
// handed to an AF_INET6 socket is simply refused. Measured: with the
// dual-stack default in place and this conversion missing, every test that
// sends to 127.0.0.1 failed or hung.
static inline void
utp_napi_addr_for_socket (int family, struct sockaddr_storage *addr) {
  if (family != AF_INET6 || addr->ss_family != AF_INET) return;

  struct sockaddr_in v4;
  memcpy(&v4, addr, sizeof(v4));

  struct sockaddr_in6 v6;
  memset(&v6, 0, sizeof(v6));
  v6.sin6_family = AF_INET6;
  v6.sin6_port = v4.sin_port;

  unsigned char *bytes = (unsigned char *) &(v6.sin6_addr);
  bytes[10] = 0xff;
  bytes[11] = 0xff;
  memcpy(bytes + 12, &(v4.sin_addr), 4);

  memset(addr, 0, sizeof(*addr));
  memcpy(addr, &v6, sizeof(v6));
}

#define UTP_NAPI_THROW(err) \
  { \
    napi_throw_error(env, uv_err_name(err), uv_strerror(err)); \
    return NULL; \
  }

#define NAPI_MAKE_CALLBACK_AND_ALLOC(env, nil, ctx, cb, n, argv, res, nread) \
  { \
    napi_status make_status = napi_make_callback(env, nil, ctx, cb, n, argv, &res); \
    if (make_status == napi_pending_exception) { \
      napi_value fatal_exception; \
      napi_get_and_clear_last_exception(env, &fatal_exception); \
      napi_fatal_exception(env, fatal_exception); \
      { \
        UTP_NAPI_CALLBACK(self->realloc, { \
          NAPI_MAKE_CALLBACK(env, nil, ctx, callback, 0, NULL, &res); \
          UTP_NAPI_BUFFER_ALLOC(self, res, 0) \
        }) \
      } \
    } else if (make_status == napi_ok) { \
      UTP_NAPI_BUFFER_ALLOC(self, res, nread) \
    } \
  }

// Every napi call in here can fail, and a napi call that fails writes NOTHING
// to the value it was handed. The original macro asked for a handle scope, a
// context and a callback, checked none of the three, and then used all three --
// so a failure at any step passed V8 whatever the stack happened to hold.
//
// This is the same fault that was fixed in on_utp_accept for 2.5.3-ttv.4 after
// four core dumps named it. It was fixed there at that ONE call site, while the
// macro every other call site goes through kept it.
//
// The scope now gates the body, and the body runs only once both references
// have resolved to a real value.
#define UTP_NAPI_CALLBACK(fn, src) \
  napi_env env = self->env; \
  napi_handle_scope scope; \
  if (napi_open_handle_scope(env, &scope) == napi_ok) { \
    napi_value ctx = NULL; \
    napi_value callback = NULL; \
    if (napi_get_reference_value(env, self->ctx, &ctx) == napi_ok && \
        napi_get_reference_value(env, fn, &callback) == napi_ok && \
        ctx != NULL && callback != NULL) { \
      src \
    } \
    napi_close_handle_scope(env, scope); \
  }

#define UTP_NAPI_BUFFER_ALLOC(self, ret, nread) \
  char *buf = NULL; \
  size_t buf_len = 0; \
  if (ret == NULL || napi_get_buffer_info(env, ret, (void **) &buf, &buf_len) != napi_ok) { \
    buf = NULL; \
    buf_len = 0; \
  } \
  if (buf_len == 0) { \
    size_t size = nread <= 0 ? 0 : nread; \
    self->buf.base += size; \
    self->buf.len -= size; \
  } else { \
    self->buf.base = buf; \
    self->buf.len = buf_len; \
  }

typedef struct {
  uint32_t min_recv_packet_size;
  uint32_t recv_packet_size;

  struct utp_iovec send_buffer[256];
  struct utp_iovec *send_buffer_next;
  uint32_t send_buffer_missing;

  utp_socket *socket;
  napi_env env;
  napi_ref ctx;
  uv_buf_t buf;
  napi_ref on_read;
  napi_ref on_drain;
  napi_ref on_end;
  napi_ref on_error;
  napi_ref on_close;
  napi_ref on_connect;
  napi_ref realloc;
  // Teardown can be reached twice: libutp announces UTP_STATE_DESTROYING from
  // ~UTPSocket(), and JavaScript calls utp_napi_connection_on_close directly
  // when a client connection is abandoned before it ever connected. The six
  // napi_delete_reference calls in the teardown are not idempotent, so a
  // second run deletes references that are already gone.
  uint32_t destroyed;
  /**
   * A strong reference to the TOKEN buffer JavaScript holds for this struct.
   *
   * libutp keeps this struct as a socket's userdata and calls into it from its
   * own timeout sweep, so its lifetime is not JavaScript's to decide either.
   * Allocated and freed by the module; the token is pointed at nothing first.
   */
  napi_ref token_ref;
} utp_napi_connection_t;

typedef struct {
  uv_udp_t handle;
  utp_context *utp;
  uint32_t accept_connections;
  utp_napi_connection_t *next_connection;
  uv_timer_t timer;
  napi_env env;
  napi_ref ctx;
  uv_buf_t buf;
  napi_ref on_message;
  napi_ref on_send;
  napi_ref on_connection;
  napi_ref on_close;
  napi_ref realloc;
  int pending_close;
  int closing;
  /**
   * Whether this environment can still be called into.
   *
   * Plain memory on purpose: every other way of asking — instance data, a
   * reference, anything through napi — needs the very environment whose
   * liveness is in question, and reading it when it is gone is the fault this
   * flag exists to prevent. Set to 1 at init, cleared by the environment's own
   * cleanup hook, and read by every callback before it touches napi.
   */
  int env_alive;
  /**
   * A strong reference to the TOKEN buffer JavaScript holds for this struct.
   *
   * The struct itself is the module's, allocated with `calloc` and freed when
   * libuv has finished with both handles. The reference exists only so that
   * the token can be pointed at nothing before the memory goes, which turns
   * every later call from JavaScript into a no-op instead of a fault.
   */
  napi_ref token_ref;
  /** Send requests belonging to this context, freed with it. */
  struct utp_napi_send_request_s *sends;
  // The address family this socket was actually bound with. Everything sent
  // from it has to be expressed in that family.
  int family;
} utp_napi_t;

typedef struct utp_napi_send_request_s {
  uv_udp_send_t req;
  napi_ref ctx;
  /** A strong reference to the token buffer, so it can be cleared on free. */
  napi_ref token_ref;
  /** Next request belonging to the same context; the context frees the chain. */
  struct utp_napi_send_request_s *next;
} utp_napi_send_request_t;

/**
 * Ownership of the native structs, and why it is not JavaScript's.
 *
 * These structs contain libuv handles and requests: `uv_udp_t` and `uv_timer_t`
 * in the context, `uv_udp_send_t` in a send request. libuv's rule is that once
 * such a thing is registered on a loop, its memory must stay valid until the
 * close or completion callback has run. Until 2.5.3-ttv.7 the structs were
 * allocated by JavaScript as `Buffer.alloc(sizeof(...))`, which put them under
 * the garbage collector — a second owner, with a different rule, and nothing
 * reconciling the two. Nine crashes came out of that gap, each a variation on
 * libuv holding a pointer into memory that had gone.
 *
 * So the module allocates them and the module frees them, at the point where
 * libuv has provably finished. JavaScript holds a TOKEN: a small buffer whose
 * only content is the pointer. Freeing writes NULL into the token first, so any
 * later call from JavaScript reads NULL and returns without doing anything,
 * rather than dereferencing a corpse.
 *
 * @param env
 * @param token - The buffer JavaScript holds.
 * @returns The struct, or NULL when it has been released.
 */
static void *
utp_napi_token_read (napi_env env, napi_value token) {
  void *data = NULL;
  size_t len = 0;
  if (napi_get_buffer_info(env, token, &data, &len) != napi_ok) return NULL;
  if (data == NULL || len < sizeof(void *)) return NULL;
  return *((void **) data);
}

/**
 * Point a token at a struct, or at nothing.
 *
 * @param env
 * @param token_ref - Reference to the token buffer; NULL is tolerated.
 * @param value - The struct, or NULL to release the token.
 * @returns {void}
 */
static void
utp_napi_token_write (napi_env env, napi_ref token_ref, void *value) {
  if (token_ref == NULL) return;
  // Its own handle scope. This is called from libuv's close callback and from
  // libutp's socket destructor, neither of which runs inside one, and reading a
  // reference creates a handle -- without a scope V8 ends the process with
  // "Cannot create a handle without a HandleScope".
  napi_handle_scope scope;
  if (napi_open_handle_scope(env, &scope) != napi_ok) return;
  napi_value token;
  if (napi_get_reference_value(env, token_ref, &token) == napi_ok && token != NULL) {
    void *data = NULL;
    size_t len = 0;
    if (napi_get_buffer_info(env, token, &data, &len) == napi_ok &&
        data != NULL && len >= sizeof(void *)) {
      *((void **) data) = value;
    }
  }
  napi_close_handle_scope(env, scope);
}

/**
 * Hand JavaScript a token for a freshly allocated struct.
 *
 * @param env
 * @param bytes - Size of the struct to allocate.
 * @param out_struct - Receives the struct.
 * @param out_token - Receives the token buffer.
 * @returns Non-zero on failure, with an error already thrown.
 */
static int
utp_napi_token_create (napi_env env, size_t bytes, void **out_struct, napi_value *out_token) {
  void *self = calloc(1, bytes);
  if (self == NULL) {
    napi_throw_error(env, NULL, "out of memory");
    return 1;
  }
  void *data = NULL;
  if (napi_create_buffer(env, sizeof(void *), &data, out_token) != napi_ok || data == NULL) {
    free(self);
    napi_throw_error(env, NULL, "could not allocate a handle token");
    return 1;
  }
  *((void **) data) = self;
  *out_struct = self;
  return 0;
}

/**
 * Read the struct a method was called on, or return without doing anything.
 *
 * A method reached after the struct was freed is not an error to report: it is
 * the ordinary consequence of teardown racing a caller, and the right answer is
 * to do nothing. Every entry point uses this, so none of them can dereference a
 * released struct.
 */
#define UTP_NAPI_ARGV_SELF(type, name, i)   type name = (type) utp_napi_token_read(env, argv[i]);   if (name == NULL) return NULL;

static void
on_sendto_free (uv_udp_send_t *req, int status) {
  free(req);
}

// libutp asserts rather than tolerating a call on a socket that is gone
// (utp_writev:3158, utp_close:3360), and before the socket pointer was cleared
// on teardown the same calls simply worked on released memory. Both answers
// are wrong; this is the question both were failing to ask.
inline static int
utp_napi_connection_gone (utp_napi_connection_t *self) {
  return self == NULL || self->destroyed || self->socket == NULL;
}

static int
utp_napi_connection_drain (utp_napi_connection_t *self) {
  // Nothing is pending on a connection that can no longer be spoken to.
  if (utp_napi_connection_gone(self)) return 1;

  struct utp_iovec *next = self->send_buffer_next;
  uint32_t missing = self->send_buffer_missing;

  if (!missing) return 1;

  int sent_bytes = utp_writev(self->socket, next, missing);
  if (sent_bytes < 0) {
    UTP_NAPI_CALLBACK(self->on_error, {
      napi_value argv[1];
      napi_create_int32(env, sent_bytes, &(argv[0]));
      NAPI_MAKE_CALLBACK(env, NULL, ctx, callback, 1, argv, NULL)
    })
    return 0;
  }

  size_t bytes = sent_bytes;

  while (bytes > 0) {
    if (next->iov_len <= bytes) {
      bytes -= next->iov_len;
      next++;
      missing--;
    } else {
      next->iov_len -= bytes;
      next->iov_base = ((char *) next->iov_base) + bytes;
      break;
    }
  }

  self->send_buffer_missing = missing;
  self->send_buffer_next = next;

  return missing ? 0 : 1;
}

inline static void
utp_napi_parse_address (struct sockaddr *name, char *ip, int *port) {
  if (name->sa_family == AF_INET6) {
    struct sockaddr_in6 *name_in6 = (struct sockaddr_in6 *) name;
    *port = ntohs(name_in6->sin6_port);

    // A dual-stack socket reports an IPv4 peer as ::ffff:1.2.3.4. Handing that
    // text upwards would change what every existing caller sees for an IPv4
    // peer, so it is unmapped back to plain IPv4 — which is also what libutp
    // does internally with its own PackedSockAddr.
    if (IN6_IS_ADDR_V4MAPPED(&(name_in6->sin6_addr))) {
      struct sockaddr_in mapped;
      memset(&mapped, 0, sizeof(mapped));
      mapped.sin_family = AF_INET;
      mapped.sin_port = name_in6->sin6_port;
      memcpy(&(mapped.sin_addr), ((const char *) &(name_in6->sin6_addr)) + 12, 4);
      uv_ip4_name(&mapped, ip, UTP_NAPI_IP_MAX);
      return;
    }

    uv_ip6_name(name_in6, ip, UTP_NAPI_IP_MAX);
    return;
  }

  struct sockaddr_in *name_in = (struct sockaddr_in *) name;
  *port = ntohs(name_in->sin_port);
  uv_ip4_name(name_in, ip, UTP_NAPI_IP_MAX);
}

/**
 * Close everything this context owns, because the environment is going away.
 *
 * The fault this exists to remove, from a core dump of 2026-08-27:
 *
 *   #0 uv_timer_stop
 *   #1 uv_close
 *   #2 node::PerIsolatePlatformData::Shutdown()
 *   #3 node::NodePlatform::UnregisterIsolate(v8::Isolate*)
 *   #4 node::worker::Worker::Run()
 *
 * Read upwards: the thread's function returned, node unregistered its isolate
 * and began closing what was left on the loop — and walked into memory that is
 * no longer there. The handles are fields of a struct that lives inside a
 * JavaScript buffer, so when the isolate's heap goes they go with it, while
 * libuv still has them registered. On the main thread this is invisible: the
 * process is ending anyway. On a worker thread the process lives on, and the
 * fault kills all of it — HTTP server, tunnel, data channels — before any
 * JavaScript handler runs.
 *
 * `napi_add_env_cleanup_hook` is early enough, which the previous note in this
 * file doubted. `Environment::RunCleanup` (node `src/env.cc`) calls
 * `CleanupHandles()`, then drains the cleanup queue — where this hook sits —
 * and then calls `CleanupHandles()` AGAIN inside the same loop. So a
 * `uv_close` issued from here is completed by that second pass, long before
 * `PerIsolatePlatformData::Shutdown` looks at the loop.
 *
 * Two things happen here and their order matters. The flag goes first, so that
 * any callback which still fires during teardown returns without touching
 * napi. Only then are the handles closed.
 *
 * @param arg - The context, as handed to `napi_add_env_cleanup_hook`.
 * @returns {void}
 */
static void
on_env_teardown (void *arg) {
  utp_napi_t *self = (utp_napi_t *) arg;
  if (self == NULL) return;

  self->env_alive = 0;

  if (self->closing) return;
  self->closing = 1;

  uv_timer_stop(&(self->timer));
  uv_udp_recv_stop(&(self->handle));

  // No close callback: it would call into JavaScript, and there is none left to
  // call. libuv only has to stop knowing about these handles.
  if (!uv_is_closing((uv_handle_t *) &(self->handle))) {
    uv_close((uv_handle_t *) &(self->handle), NULL);
  }
  if (!uv_is_closing((uv_handle_t *) &(self->timer))) {
    uv_close((uv_handle_t *) &(self->timer), NULL);
  }
}

/**
 * Whether it is still legal to call into JavaScript for this context.
 *
 * Every callback below reaches napi sooner or later, and every one of them can
 * fire while the environment is being torn down: libuv keeps delivering, and
 * libutp keeps sweeping its timeouts, until their handles are closed. Reading
 * a plain int costs nothing and is the only check that does not itself need
 * the environment.
 *
 * @param self - The context, or NULL when the callback could not find one.
 * @returns Non-zero while the environment can be called into.
 */
static inline int
utp_napi_can_call_js (utp_napi_t *self) {
  return self != NULL && self->env_alive;
}

static void
on_uv_interval (uv_timer_t *req) {
  utp_napi_t *self = (utp_napi_t *) req->data;
  if (!utp_napi_can_call_js(self)) return;
  utp_issue_deferred_acks(self->utp);
  utp_check_timeouts(self->utp);
}

static void
on_uv_alloc (uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  utp_napi_t *self = (utp_napi_t *) handle->data;
  // The read buffer is JavaScript memory too. With the environment gone there
  // is nowhere to put a datagram, so libuv is told there is no room.
  if (!utp_napi_can_call_js(self)) {
    buf->base = NULL;
    buf->len = 0;
    return;
  }
  *buf = self->buf;
}

static void
on_uv_read (uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
  utp_napi_t *self = (utp_napi_t *) handle->data;
  // This is the callback the 2026-08-27 crash arrived through: a datagram, then
  // libutp's timeout sweep, then a socket destructor, then napi on a dead
  // environment. Nothing below is safe once the environment is going.
  if (!utp_napi_can_call_js(self)) return;

  // TODO: is this overkill to call here?
  // we do it because ucat.c does it
  utp_check_timeouts(self->utp);
  if (self->closing) return;

  if (nread == 0) {
    utp_issue_deferred_acks(self->utp);
    return;
  }

  if (nread > 0 && addr != NULL) {
    const unsigned char *base = (const unsigned char *) buf->base;
    if (utp_process_udp(self->utp, base, nread, addr, utp_napi_addr_len(addr))) return;
  }

  // libuv documents `addr` as nullable, and it is null whenever the read
  // itself failed — that case arrives as `nread < 0`. The two branches above
  // return only for `nread == 0` and for a datagram libutp consumed, so a
  // failed read fell through to the parse below, which dereferences the
  // pointer without checking it. Segmentation fault in the UDP read callback,
  // on whichever thread owns the socket.
  //
  // There is nothing to give JavaScript here: no sender, and no payload. The
  // part of this callback that must run on every wake-up is
  // `utp_check_timeouts`, and that has already run above.
  if (nread < 0 || addr == NULL) return;

  int port;
  char ip[UTP_NAPI_IP_MAX];
  utp_napi_parse_address((struct sockaddr *) addr, ip, &port);

  UTP_NAPI_CALLBACK(self->on_message, {
    napi_value ret = NULL;
    napi_value argv[3];
    napi_create_int32(env, nread, &(argv[0]));
    napi_create_uint32(env, port, &(argv[1]));
    napi_create_string_utf8(env, ip, NAPI_AUTO_LENGTH, &(argv[2]));
    NAPI_MAKE_CALLBACK_AND_ALLOC(env, NULL, ctx, callback, 3, argv, ret, nread)
  })
}

static void
on_uv_close (uv_handle_t *handle) {
  utp_napi_t *self = (utp_napi_t *) handle->data;

  self->pending_close--;
  if (self->pending_close > 0) return;

  // The environment cleanup hook goes FIRST, and this is the defect that the
  // core dump of 2026-08-27 21:10 was made of.
  //
  // The hook is registered per context at init and holds a raw pointer to it.
  // Releasing the reference below lets the collector free that memory, and the
  // hook stayed registered against it. At teardown the hook then ran on freed
  // memory: it wrote its flag there, read a stale `closing`, and called
  // `uv_close` on handles that no longer existed -- pushing a dead handle into
  // the loop's closing machinery. The fault surfaced later and elsewhere, when
  // `uv__finish_close` unlinked a HEALTHY handle and its neighbour in
  // `loop->handle_queue` was that dead one:
  //
  //   #0  QUEUE_REMOVE, str x1,[x0,#8]   -- x0 unmapped
  //   #1  uv__finish_close
  //   ..  node::worker::Worker::Run()
  //
  // Read in the dump: the handle being closed was type 15 (UV_UDP) with
  // `data` pointing at itself, which is this struct; its queue neighbour lay
  // at an address in the same region that gdb could not read at all.
  napi_remove_env_cleanup_hook(self->env, on_env_teardown, self);

  // libuv has finished with both handles. This is the only place the context
  // is freed, and it is reached only from libuv's own close callback, which
  // `uv__finish_close` calls AFTER unlinking the handle from the loop. So there
  // is no moment at which the loop holds a pointer into freed memory.
  //
  // The environment being gone is the one case where nothing is freed: the
  // process is ending, JavaScript will not run again, and a deliberate leak at
  // that point is better in every way than touching napi during teardown.
  if (!utp_napi_can_call_js(self)) return;

  // JavaScript first, while the struct is still whole: `_onclose` calls
  // `utp_napi_destroy`, which needs it.
  UTP_NAPI_CALLBACK(self->on_close, {
    NAPI_MAKE_CALLBACK(env, NULL, ctx, callback, 0, NULL, NULL);
  })

  // Send requests carry `uv_udp_send_t`, which is a libuv REQUEST and lives
  // under the same rule as a handle. The socket is closed, so libuv has
  // completed or cancelled every one of them.
  utp_napi_send_request_t *send_req = self->sends;
  while (send_req != NULL) {
    utp_napi_send_request_t *next = send_req->next;
    utp_napi_token_write(self->env, send_req->token_ref, NULL);
    if (send_req->token_ref != NULL) napi_delete_reference(self->env, send_req->token_ref);
    free(send_req);
    send_req = next;
  }
  self->sends = NULL;

  // Point the token at nothing BEFORE freeing, so a call that arrives after
  // this reads NULL and does nothing.
  utp_napi_token_write(self->env, self->token_ref, NULL);
  if (self->token_ref != NULL) {
    napi_delete_reference(self->env, self->token_ref);
    self->token_ref = NULL;
  }
  free(self);
}

static void
on_uv_send (uv_udp_send_t *req, int status) {
  uv_udp_t *handle = req->handle;
  utp_napi_t *self = (utp_napi_t *) handle->data;
  if (!utp_napi_can_call_js(self)) return;
  utp_napi_send_request_t *send = (utp_napi_send_request_t *) req->data;

  UTP_NAPI_CALLBACK(self->on_send, {
    napi_value argv[2];
    napi_get_reference_value(env, send->ctx, &(argv[0]));
    napi_create_int32(env, status, &(argv[1]));
    NAPI_MAKE_CALLBACK(env, NULL, ctx, callback, 2, argv, NULL);
  })
}

static uint64
on_utp_firewall (utp_callback_arguments *a) {
  utp_napi_t *self = (utp_napi_t *) utp_context_get_userdata(a->context);

  // Refuse rather than dereference. Non-zero means "do not accept". A context
  // whose environment has gone refuses everything: an accepted connection
  // would need JavaScript to own it.
  if (!utp_napi_can_call_js(self)) return 1;

  return self->accept_connections ? 0 : 1;
}

inline static void
utp_napi_connection_destroy (utp_napi_connection_t *self) {
  if (self == NULL || self->destroyed) return;
  self->destroyed = 1;

  // The socket must stop pointing back at this struct BEFORE anything is
  // released. libutp goes on delivering callbacks for a socket it is in the
  // middle of destroying, and every one of them begins by reading this
  // pointer; leaving it in place is what lets a later callback walk into
  // memory whose napi references have just been deleted.
  if (self->socket != NULL) {
    utp_set_userdata(self->socket, NULL);
    self->socket = NULL;
  }

  UTP_NAPI_CALLBACK(self->on_close, {
    NAPI_MAKE_CALLBACK(env, NULL, ctx, callback, 0, NULL, NULL)
  })

  self->buf.base = NULL;
  self->buf.len = 0;

  napi_delete_reference(self->env, self->ctx);
  napi_delete_reference(self->env, self->on_read);
  napi_delete_reference(self->env, self->on_drain);
  napi_delete_reference(self->env, self->on_end);
  napi_delete_reference(self->env, self->on_error);
  napi_delete_reference(self->env, self->on_close);
  napi_delete_reference(self->env, self->realloc);

  // The socket no longer points here and every reference is gone, so nothing
  // native can reach this struct again. Point the token at nothing first, so a
  // late call from JavaScript reads NULL and returns, and only then free.
  utp_napi_token_write(self->env, self->token_ref, NULL);
  if (self->token_ref != NULL) {
    napi_delete_reference(self->env, self->token_ref);
    self->token_ref = NULL;
  }
  free(self);
}

/**
 * Whether a CONNECTION callback may call into JavaScript.
 *
 * A connection struct carries no pointer back to its context, but every libutp
 * callback is handed the context it belongs to, so the same plain-int check is
 * available here. Both halves are required: a connection whose socket carries
 * no userdata, and a context whose environment has gone.
 *
 * @param a - The callback arguments libutp passed in.
 * @param self - The connection read from the socket's userdata.
 * @returns Non-zero while it is safe to touch napi.
 */
static inline int
utp_napi_connection_can_call_js (utp_callback_arguments *a, utp_napi_connection_t *self) {
  if (self == NULL) return 0;
  return utp_napi_can_call_js((utp_napi_t *) utp_context_get_userdata(a->context));
}

static uint64
on_utp_state_change (utp_callback_arguments *a) {
  utp_napi_connection_t *self = (utp_napi_connection_t *) utp_get_userdata(a->socket);

  // A socket without userdata is not hypothetical, and the guard added in
  // 2.5.3-ttv.4 is one of the ways it arises: an incoming connection arriving
  // while JavaScript has supplied no buffer for the next one is refused BEFORE
  // utp_set_userdata is reached, so the socket exists with nothing attached --
  // and its ~UTPSocket() still announces UTP_STATE_DESTROYING. A socket the
  // firewall callback rejects is another way.
  //
  // Field evidence, 2026-08-26, one core dump on a Raspberry-class host:
  //
  //   #0 v8::HandleScope::HandleScope(v8::Isolate*)
  //   #1 napi_open_handle_scope ()
  //   #2 on_utp_state_change(utp_callback_arguments*)   utp_native.node
  //   #3 utp_call_on_state_change(...)
  //   #4 UTPSocket::~UTPSocket()
  //   #5 utp_check_timeouts ()
  //   #6 on_uv_read(uv_udp_s*, ...)
  //
  // Read upwards: a datagram arrived, libutp swept its timeouts, destroyed a
  // socket, and the destructor called in here -- where self->env was read off a
  // pointer that had never been set. The whole proxy died with it, since a
  // fault on any thread ends the process.
  if (!utp_napi_connection_can_call_js(a, self)) return 0;

  switch (a->state) {
    case UTP_STATE_CONNECT: {
      UTP_NAPI_CALLBACK(self->on_connect, {
        NAPI_MAKE_CALLBACK(env, NULL, ctx, callback, 0, NULL, NULL)
      })
      break;
    }

    case UTP_STATE_WRITABLE: {
      if (utp_napi_connection_drain(self)) {
        UTP_NAPI_CALLBACK(self->on_drain, {
          NAPI_MAKE_CALLBACK(env, NULL, ctx, callback, 0, NULL, NULL)
        })
      }
      break;
    }

    case UTP_STATE_EOF: {
      if (self->recv_packet_size) {
        UTP_NAPI_CALLBACK(self->on_read, {
          napi_value ret = NULL;
          napi_value argv[1];
          napi_create_uint32(env, self->recv_packet_size, &(argv[0]));
          NAPI_MAKE_CALLBACK_AND_ALLOC(env, NULL, ctx, callback, 1, argv, ret, self->recv_packet_size)
          self->recv_packet_size = 0;
        })
      }
      UTP_NAPI_CALLBACK(self->on_end, {
        NAPI_MAKE_CALLBACK(env, NULL, ctx, callback, 0, NULL, NULL)
      })
      break;
    }

    case UTP_STATE_DESTROYING: {
      utp_napi_connection_destroy(self);
      break;
    }

    default: {
      printf("on_utp_statechange (unkown state: %i)\n", a->state);
      break;
    }
  }

  return 0;
}

static uint64
on_utp_accept (utp_callback_arguments *a) {
  utp_napi_t *self = (utp_napi_t *) utp_context_get_userdata(a->context);
  if (!utp_napi_can_call_js(self)) return 0;

  // No buffer to put this connection in means it cannot be accepted. That is
  // not a hypothetical: the buffer for the NEXT connection comes back from
  // JavaScript at the end of this function, and every way that can fail leaves
  // nothing here. Dereferencing it anyway is a null write on the thread that
  // owns the socket.
  if (self->next_connection == NULL) return 0;

  // sockaddr is too small to hold an IPv6 peer; sockaddr_storage is the type
  // that is guaranteed to hold any of them.
  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  utp_getpeername(a->socket, (struct sockaddr *) &addr, &addr_len);

  int port;
  char ip[UTP_NAPI_IP_MAX];
  utp_napi_parse_address((struct sockaddr *) &addr, ip, &port);

  self->next_connection->socket = a->socket;
  utp_set_userdata(a->socket, self->next_connection);

  UTP_NAPI_CALLBACK(self->on_connection, {
    napi_value argv[2];
    napi_create_uint32(env, port, &(argv[0]));
    napi_create_string_utf8(env, ip, NAPI_AUTO_LENGTH, &(argv[1]));
    // Initialised, and the call's own answer is read.
    //
    // `NAPI_MAKE_CALLBACK` examines exactly one failure — `napi_pending_exception`
    // — and even for that one it reports the exception and CARRIES ON. Every
    // other status, `napi_invalid_arg` among them, is discarded, and in none of
    // these cases does napi write anything to `res`. The next line then handed
    // that value to `napi_get_buffer_info`, which asks V8 what it is; on an
    // uninitialised handle that is a dereference of whatever the stack held.
    //
    // Field evidence, four core dumps on a Raspberry-class host, all on the
    // thread owning the uTP socket and all with the same top frames:
    //
    //   #0 v8::Value::IsArrayBufferView() const
    //   #1 napi_get_buffer_info ()
    //   #2 on_utp_accept(utp_callback_arguments*)   utp_native.node
    //   #3 utp_call_on_accept(...)
    //   #4 utp_process_udp ()
    //   #5 on_uv_read(uv_udp_s*, ...)
    //
    // They differ only below that. Two sat over `SpinEventLoopInternal` — the
    // ordinary event loop — and two over `Environment::CleanupHandles` inside
    // `FreeEnvironment`. That looked like two separate faults for two days. It
    // is one, and node's own sources say why:
    //
    //   * `FreeEnvironment` sets `can_call_into_js(false)` BEFORE it calls
    //     `RunCleanup` (`src/api/environment.cc`);
    //   * `napi_make_callback` returns `napi_generic_failure` through
    //     `CHECK_MAYBE_EMPTY` when `MakeCallback` yields an empty result, and
    //     that early return writes nothing to `*result` (`src/node_api.cc`).
    //
    // So teardown is simply one of the ways this call fails without answering.
    //
    // This paragraph used to end by dismissing `napi_add_env_cleanup_hook` —
    // "`RunCleanup` drains the cleanup queue only AFTER `CleanupHandles`". Read
    // again in node `src/env.cc`, that is half the ordering: `RunCleanup` calls
    // `CleanupHandles()`, THEN drains the cleanup queue, and then calls
    // `CleanupHandles()` again in the same loop. A hook is therefore early
    // enough to take handles off the loop, and one is registered now
    // (`on_env_teardown`). It does not make the guard below unnecessary — a
    // callback can still arrive between the hook running and the handle
    // closing — which is why both exist.
    //
    // The comment this replaces read "will never throw due to the event being
    // NTed in js". Whether it throws is beside the point — the value is unset
    // either way.
    napi_value next = NULL;
    napi_status accept_status =
      napi_make_callback(env, NULL, ctx, callback, 2, argv, &next);
    if (accept_status == napi_pending_exception) {
      napi_value fatal_exception;
      napi_get_and_clear_last_exception(env, &fatal_exception);
      napi_fatal_exception(env, fatal_exception);
    }
    utp_napi_connection_t *connection = accept_status == napi_ok && next != NULL
      ? (utp_napi_connection_t *) utp_napi_token_read(env, next)
      : NULL;
    if (connection != NULL) {
      self->next_connection = connection;
    } else {
      // Nothing usable came back. The buffer that was here has just been given
      // to the connection accepted above, so keeping it would hand the same
      // memory to two connections. Cleared instead, and the guard at the top
      // refuses further accepts until JavaScript supplies another one.
      self->next_connection = NULL;
    }
  })

  return 0;
}

static uint64
on_utp_error (utp_callback_arguments *a) {
  utp_napi_connection_t *self = (utp_napi_connection_t *) utp_get_userdata(a->socket);
  if (!utp_napi_connection_can_call_js(a, self)) return 0;

  // Same exposure as on_utp_state_change: an error can be reported for a socket
  // that never had a connection attached, and there is no one to tell.
  if (self == NULL) return 0;

  UTP_NAPI_CALLBACK(self->on_error, {
    napi_value argv[1];
    napi_create_int32(env, a->error_code, &(argv[0]));
    NAPI_MAKE_CALLBACK(env, NULL, ctx, callback, 1, argv, NULL)
  })

  return 0;
}

static uint64
on_utp_read (utp_callback_arguments *a) {
  utp_napi_connection_t *self = (utp_napi_connection_t *) utp_get_userdata(a->socket);
  if (!utp_napi_connection_can_call_js(a, self)) return 0;

  if (self == NULL) return 0;

  // The copy below used to be written without once consulting the size of the
  // buffer it was writing into. self->buf.len is maintained on every hand-off
  // to JavaScript (UTP_NAPI_BUFFER_ALLOC either sets it, or advances base and
  // shrinks len by what was consumed) and was simply never read here, so a peer
  // sending more between two hand-offs than the current buffer still holds
  // wrote past its end.
  //
  // That is a heap overwrite, and a heap overwrite does not fault where it
  // happens -- it faults later, inside whatever structure occupied the memory.
  // It is the best candidate for the deaths of 2026-08-18..25 that all landed
  // in libuv's own bookkeeping (uv_timer_stop under
  // PerIsolatePlatformData::Shutdown) with no explanation of how those
  // structures came to be corrupt.
  //
  // Data is not dropped to make room: what has accumulated is handed to
  // JavaScript, which answers with a fresh buffer, and the rest of the packet
  // goes into that. Dropping bytes libutp has already acknowledged would
  // corrupt the stream silently, which is worse than the crash.
  const unsigned char *chunk = (const unsigned char *) a->buf;
  size_t remaining = a->len;
  int handovers = 0;

  while (remaining > 0) {
    size_t room = self->buf.len > self->recv_packet_size
      ? self->buf.len - self->recv_packet_size
      : 0;

    if (room == 0) {
      // Two hand-offs in a row that freed no room mean JavaScript is not
      // supplying a usable buffer. Writing anyway is the fault this guard
      // exists to prevent, so the connection is told instead.
      if (self->recv_packet_size == 0 || handovers >= 2) {
        UTP_NAPI_CALLBACK(self->on_error, {
          napi_value argv[1];
          napi_create_int32(env, UV_ENOBUFS, &(argv[0]));
          NAPI_MAKE_CALLBACK(env, NULL, ctx, callback, 1, argv, NULL)
        })
        return 0;
      }
      {
        UTP_NAPI_CALLBACK(self->on_read, {
          napi_value ret = NULL;
          napi_value argv[1];
          napi_create_uint32(env, self->recv_packet_size, &(argv[0]));
          NAPI_MAKE_CALLBACK_AND_ALLOC(env, NULL, ctx, callback, 1, argv, ret, self->recv_packet_size)
          self->recv_packet_size = 0;
        })
      }
      handovers++;
      continue;
    }

    size_t take = remaining < room ? remaining : room;
    memcpy(self->buf.base + self->recv_packet_size, chunk, take);
    self->recv_packet_size += take;
    chunk += take;
    remaining -= take;
    handovers = 0;
  }

  if (self->recv_packet_size < self->min_recv_packet_size) {
    return 0;
  }

  UTP_NAPI_CALLBACK(self->on_read, {
    napi_value ret = NULL;
    napi_value argv[1];
    napi_create_uint32(env, self->recv_packet_size, &(argv[0]));
    NAPI_MAKE_CALLBACK_AND_ALLOC(env, NULL, ctx, callback, 1, argv, ret, self->recv_packet_size)
    self->recv_packet_size = 0;
  })

  return 0;
}

static uint64
on_utp_sendto (utp_callback_arguments *a) {
  utp_napi_t *self = (utp_napi_t *) utp_context_get_userdata(a->context);
  // Sending needs the read buffer and the send path, both JavaScript memory.
  if (!utp_napi_can_call_js(self)) return 0;
  uv_buf_t buf = uv_buf_init((char *) a->buf, a->len);

  if (uv_udp_try_send(&(self->handle), &buf, 1, a->address) >= 0) return 0;

  char *cpy = (char *) malloc(sizeof(uv_udp_send_t) + a->len);

  // Out of memory is a dropped datagram -- uTP retransmits -- not a null write.
  if (cpy == NULL) return 0;

  buf.base = cpy + sizeof(uv_udp_send_t);
  memcpy(buf.base, a->buf, a->len);

  uv_udp_send((uv_udp_send_t *) cpy, &(self->handle), &buf, 1, a->address, on_sendto_free);

  return 0;
}

/**
 * Allocate a context and hand JavaScript a token for it.
 *
 * Separate from `utp_napi_init` because the token has to exist before init can
 * be given it, and because allocation is the module's job now.
 *
 * @returns The token buffer.
 */
NAPI_METHOD(utp_napi_alloc) {
  void *self = NULL;
  napi_value token;
  if (utp_napi_token_create(env, sizeof(utp_napi_t), &self, &token)) return NULL;
  return token;
}

/**
 * Allocate a connection and hand JavaScript a token for it.
 *
 * @returns The token buffer.
 */
NAPI_METHOD(utp_napi_connection_alloc) {
  void *self = NULL;
  napi_value token;
  if (utp_napi_token_create(env, sizeof(utp_napi_connection_t), &self, &token)) return NULL;
  napi_create_reference(env, token, 1, &(((utp_napi_connection_t *) self)->token_ref));
  return token;
}

/**
 * Allocate a send request and hand JavaScript a token for it.
 *
 * The request is linked onto its context, which frees the whole chain when
 * libuv has finished with the socket. A `uv_udp_send_t` is a libuv REQUEST and
 * carries the same rule as a handle: the memory must outlive the operation.
 *
 * @returns The token buffer.
 */
NAPI_METHOD(utp_napi_send_request_alloc) {
  NAPI_ARGV(1)
  UTP_NAPI_ARGV_SELF(utp_napi_t *, self, 0)

  void *request = NULL;
  napi_value token;
  if (utp_napi_token_create(env, sizeof(utp_napi_send_request_t), &request, &token)) return NULL;

  utp_napi_send_request_t *send_req = (utp_napi_send_request_t *) request;
  napi_create_reference(env, token, 1, &(send_req->token_ref));
  send_req->next = self->sends;
  self->sends = send_req;
  return token;
}

/**
 * Whether the context accepts incoming connections.
 *
 * JavaScript used to write this field through a `Uint32Array` laid over the
 * struct's own bytes. It cannot any more — the struct is not in a buffer it can
 * see — and a setter is the honest way to expose one field rather than the
 * whole of memory.
 *
 * @returns {void}
 */
NAPI_METHOD(utp_napi_set_accept_connections) {
  NAPI_ARGV(2)
  UTP_NAPI_ARGV_SELF(utp_napi_t *, self, 0)
  NAPI_ARGV_UINT32(accept, 1)

  self->accept_connections = accept;
  return NULL;
}

/**
 * The smallest packet this connection will accept before asking for more room.
 *
 * JavaScript used to write this through a `Uint32Array` laid over the struct's
 * first two words. It cannot any more, and one field exposed deliberately is
 * better than the whole of memory exposed by accident.
 *
 * @returns {void}
 */
NAPI_METHOD(utp_napi_connection_set_min_recv_packet_size) {
  NAPI_ARGV(2)
  UTP_NAPI_ARGV_SELF(utp_napi_connection_t *, self, 0)
  NAPI_ARGV_UINT32(size, 1)

  self->min_recv_packet_size = size;
  return NULL;
}

NAPI_METHOD(utp_napi_init) {
  NAPI_ARGV(9)
  UTP_NAPI_ARGV_SELF(utp_napi_t *, self, 0)

  self->closing = 0;
  self->pending_close = 2;
  self->family = AF_UNSPEC;
  self->env = env;
  self->env_alive = 1;
  self->token_ref = NULL;
  napi_create_reference(env, argv[1], 1, &(self->ctx));

  // Hold the TOKEN, so that the pointer inside it can be cleared before this
  // struct is freed. The struct's own lifetime no longer depends on the
  // collector at all: it is allocated by `utp_napi_alloc` and freed once libuv
  // has finished with both handles.
  napi_create_reference(env, argv[0], 1, &(self->token_ref));
  self->sends = NULL;

  // And be told before the environment goes, so the handles come off the loop
  // while there is still a loop to take them off. See on_env_teardown.
  napi_add_env_cleanup_hook(env, on_env_teardown, self);

  UTP_NAPI_ARGV_SELF(utp_napi_connection_t *, next, 2)
  self->next_connection = next;

  uv_timer_t *timer = &(self->timer);
  timer->data = self;

  struct uv_loop_s *loop;
  napi_get_uv_event_loop(env, &loop);

  int err = uv_timer_init(loop, timer);
  if (err < 0) UTP_NAPI_THROW(err)

  NAPI_ARGV_BUFFER(buf, 3)
  self->buf.base = buf;
  self->buf.len = buf_len;

  uv_udp_t *handle = &(self->handle);
  handle->data = self;

  err = uv_udp_init(loop, handle);
  if (err < 0) UTP_NAPI_THROW(err)

  napi_create_reference(env, argv[4], 1, &(self->on_message));
  napi_create_reference(env, argv[5], 1, &(self->on_send));
  napi_create_reference(env, argv[6], 1, &(self->on_connection));
  napi_create_reference(env, argv[7], 1, &(self->on_close));
  napi_create_reference(env, argv[8], 1, &(self->realloc));

  self->utp = utp_init(2);
  utp_context_set_userdata(self->utp, self);

  utp_set_callback(self->utp, UTP_ON_STATE_CHANGE, &on_utp_state_change);
  utp_set_callback(self->utp, UTP_ON_READ, &on_utp_read);
  utp_set_callback(self->utp, UTP_ON_FIREWALL, &on_utp_firewall);
  utp_set_callback(self->utp, UTP_ON_ACCEPT, &on_utp_accept);
  utp_set_callback(self->utp, UTP_SENDTO, &on_utp_sendto);
  utp_set_callback(self->utp, UTP_ON_ERROR, &on_utp_error);

  self->accept_connections = 0;

  return NULL;
}

NAPI_METHOD(utp_napi_close) {
  NAPI_ARGV(1)
  UTP_NAPI_ARGV_SELF(utp_napi_t *, self, 0)

  self->closing = 1;

  int err;

  err = uv_timer_stop(&(self->timer));
  if (err < 0) UTP_NAPI_THROW(err)

  err = uv_udp_recv_stop(&(self->handle));
  if (err < 0) UTP_NAPI_THROW(err)

  uv_close((uv_handle_t *) &(self->handle), on_uv_close);
  uv_close((uv_handle_t *) &(self->timer), on_uv_close);

  return NULL;
}

NAPI_METHOD(utp_napi_destroy) {
  NAPI_ARGV(2)
  UTP_NAPI_ARGV_SELF(utp_napi_t *, self, 0)
  napi_value send_reqs = argv[1];

  self->buf.base = NULL;
  self->buf.len = 0;

  napi_delete_reference(env, self->ctx);
  napi_delete_reference(env, self->on_message);
  napi_delete_reference(env, self->on_send);
  napi_delete_reference(env, self->on_connection);
  napi_delete_reference(env, self->on_close);
  napi_delete_reference(env, self->realloc);

  // The array holds tokens now, not the structs themselves. A token that has
  // already been released reads NULL and is skipped: a send request can be
  // freed before this runs only if the context was, and then nothing would be
  // calling here at all.
  NAPI_FOR_EACH(send_reqs, el) {
    utp_napi_send_request_t *send_req = (utp_napi_send_request_t *) utp_napi_token_read(env, el);
    if (send_req == NULL) continue;
    if (send_req->ctx != NULL) {
      napi_delete_reference(env, send_req->ctx);
      send_req->ctx = NULL;
    }
  }

  // The hook holds a pointer to this struct. Once JavaScript has destroyed the
  // context the struct is about to go, so the hook must not survive it — a
  // cleanup hook left registered fires later against freed memory, which is the
  // very shape this change exists to remove.
  napi_remove_env_cleanup_hook(env, on_env_teardown, self);

  utp_destroy(self->utp);
  self->utp = NULL;

  return NULL;
}

NAPI_METHOD(utp_napi_bind) {
  NAPI_ARGV(3)
  UTP_NAPI_ARGV_SELF(utp_napi_t *, self, 0)
  NAPI_ARGV_UINT32(port, 1)
  NAPI_ARGV_UTF8(ip, UTP_NAPI_IP_MAX, 2)

  uv_udp_t *handle = &(self->handle);

  int err;
  struct sockaddr_storage addr;

  err = utp_napi_addr_from_text((char *) &ip, port, &addr);
  if (err < 0) UTP_NAPI_THROW(err)

  // No UV_UDP_IPV6ONLY: a socket bound to :: then carries IPv4 peers too, as
  // v4-mapped addresses, which utp_napi_parse_address unmaps on the way out.
  err = uv_udp_bind(handle, (const struct sockaddr*) &addr, 0);
  if (err < 0) UTP_NAPI_THROW(err)

  self->family = addr.ss_family;

  // TODO: We should close the handle here also if this fails
  err = uv_udp_recv_start(handle, on_uv_alloc, on_uv_read);
  if (err < 0) UTP_NAPI_THROW(err)

  // TODO: same as above
  err = uv_timer_start(&(self->timer), on_uv_interval, UTP_NAPI_TIMEOUT_INTERVAL, UTP_NAPI_TIMEOUT_INTERVAL);
  if (err < 0) UTP_NAPI_THROW(err)

  uv_unref((uv_handle_t *) &(self->timer));

  return NULL;
}

NAPI_METHOD(utp_napi_local_port) {
  NAPI_ARGV(1)
  UTP_NAPI_ARGV_SELF(utp_napi_t *, self, 0)

  int err;
  struct sockaddr_storage name;
  int name_len = sizeof(name);

  err = uv_udp_getsockname(&(self->handle), (struct sockaddr *) &name, &name_len);
  if (err < 0) UTP_NAPI_THROW(err)

  int port = name.ss_family == AF_INET6
    ? ntohs(((struct sockaddr_in6 *) &name)->sin6_port)
    : ntohs(((struct sockaddr_in *) &name)->sin_port);

  NAPI_RETURN_UINT32(port)
}

NAPI_METHOD(utp_napi_send_request_init) {
  NAPI_ARGV(2)
  UTP_NAPI_ARGV_SELF(utp_napi_send_request_t *, send_req, 0)

  uv_udp_send_t *req = &(send_req->req);
  req->data = send_req;

  napi_create_reference(env, argv[1], 1, &(send_req->ctx));

  return NULL;
}

NAPI_METHOD(utp_napi_send) {
  NAPI_ARGV(7)
  UTP_NAPI_ARGV_SELF(utp_napi_t *, self, 0)
  UTP_NAPI_ARGV_SELF(utp_napi_send_request_t *, send_req, 1)
  NAPI_ARGV_BUFFER(buf, 2)
  NAPI_ARGV_UINT32(offset, 3)
  NAPI_ARGV_UINT32(len, 4)
  NAPI_ARGV_UINT32(port, 5)
  NAPI_ARGV_UTF8(ip, UTP_NAPI_IP_MAX, 6)

  uv_udp_send_t *req = &(send_req->req);

  uv_buf_t bufs = {};
  bufs.base = buf + offset;
  bufs.len = len;

  struct sockaddr_storage addr;
  int err;

  err = utp_napi_addr_from_text((char *) &ip, port, &addr);
  if (err) UTP_NAPI_THROW(err)

  utp_napi_addr_for_socket(self->family, &addr);

  err = uv_udp_send(req, &(self->handle), &bufs, 1, (const struct sockaddr *) &addr, on_uv_send);
  if (err) UTP_NAPI_THROW(err)

  return NULL;
}

NAPI_METHOD(utp_napi_ref) {
  NAPI_ARGV(1)
  UTP_NAPI_ARGV_SELF(utp_napi_t *, self, 0)

  uv_ref((uv_handle_t *) &(self->handle));

  return NULL;
}

NAPI_METHOD(utp_napi_unref) {
  NAPI_ARGV(1)
  UTP_NAPI_ARGV_SELF(utp_napi_t *, self, 0)

  uv_unref((uv_handle_t *) &(self->handle));

  return NULL;
}

NAPI_METHOD(utp_napi_recv_buffer) {
  NAPI_ARGV(2)
  UTP_NAPI_ARGV_SELF(utp_napi_t *, self, 0)
  NAPI_ARGV_INT32(size, 1)

  int err;
  NAPI_UV_THROWS(err, uv_recv_buffer_size((uv_handle_t *) &(self->handle), &size))

  NAPI_RETURN_INT32(size)
}

NAPI_METHOD(utp_napi_send_buffer) {
  NAPI_ARGV(2)
  UTP_NAPI_ARGV_SELF(utp_napi_t *, self, 0)
  NAPI_ARGV_INT32(size, 1)

  int err;
  NAPI_UV_THROWS(err, uv_send_buffer_size((uv_handle_t *) &(self->handle), &size))

  NAPI_RETURN_INT32(size)
}

NAPI_METHOD(utp_napi_set_ttl) {
  NAPI_ARGV(2)
  UTP_NAPI_ARGV_SELF(utp_napi_t *, self, 0)
  NAPI_ARGV_UINT32(ttl, 1)

  int err;
  NAPI_UV_THROWS(err, uv_udp_set_ttl(&(self->handle), ttl))

  return NULL;
}

NAPI_METHOD(utp_napi_connection_init) {
  NAPI_ARGV(10)
  UTP_NAPI_ARGV_SELF(utp_napi_connection_t *, self, 0)

  self->env = env;

  napi_create_reference(env, argv[1], 1, &(self->ctx));

  NAPI_ARGV_BUFFER(buf, 2)
  self->buf.base = buf;
  self->buf.len = buf_len;

  napi_create_reference(env, argv[3], 1, &(self->on_read));
  napi_create_reference(env, argv[4], 1, &(self->on_drain));
  napi_create_reference(env, argv[5], 1, &(self->on_end));
  napi_create_reference(env, argv[6], 1, &(self->on_error));
  napi_create_reference(env, argv[7], 1, &(self->on_close));
  napi_create_reference(env, argv[8], 1, &(self->on_connect));
  napi_create_reference(env, argv[9], 1, &(self->realloc));

  return NULL;
}

NAPI_METHOD(utp_napi_connection_on_close) {
  // To trigger a manual teardown if connect was never called
  // on a client connection
  NAPI_ARGV(1)
  UTP_NAPI_ARGV_SELF(utp_napi_connection_t *, self, 0)
  utp_napi_connection_destroy(self);
  return NULL;
}

NAPI_METHOD(utp_napi_connection_write) {
  NAPI_ARGV(2)
  UTP_NAPI_ARGV_SELF(utp_napi_connection_t *, self, 0)
  NAPI_ARGV_BUFFER(buf, 1)

  // A write that arrives after teardown is a write to a closed socket. The
  // stream has already been ended on the JavaScript side by on_close, so it is
  // reported as drained: nothing is left pending, and nothing waits for an
  // on_drain that can never come.
  if (utp_napi_connection_gone(self)) { NAPI_RETURN_UINT32(1) }

  self->send_buffer_next = self->send_buffer;
  self->send_buffer_next->iov_base = buf;
  self->send_buffer_next->iov_len = buf_len;
  self->send_buffer_missing = 1;

  int drained = utp_napi_connection_drain(self);
  NAPI_RETURN_UINT32(drained)
}

NAPI_METHOD(utp_napi_connection_writev) {
  NAPI_ARGV(2)
  UTP_NAPI_ARGV_SELF(utp_napi_connection_t *, self, 0)

  // Same as utp_napi_connection_write above.
  if (utp_napi_connection_gone(self)) { NAPI_RETURN_UINT32(1) }

  napi_value bufs = argv[1];
  struct utp_iovec *next = self->send_buffer_next = self->send_buffer;

  NAPI_FOR_EACH(bufs, el) {
    NAPI_BUFFER(buf, el)

    next->iov_base = buf;
    next->iov_len = buf_len;
    next++;
  }

  self->send_buffer_missing = bufs_len;

  int drained = utp_napi_connection_drain(self);
  NAPI_RETURN_UINT32(drained)
}

NAPI_METHOD(utp_napi_connection_shutdown) {
  NAPI_ARGV(1)
  UTP_NAPI_ARGV_SELF(utp_napi_connection_t *, self, 0)

  // Already shut down as far as anyone can tell.
  if (utp_napi_connection_gone(self)) return NULL;

  utp_shutdown(self->socket, SHUT_WR);

  return NULL;
}

NAPI_METHOD(utp_napi_connection_close) {
  NAPI_ARGV(1)
  UTP_NAPI_ARGV_SELF(utp_napi_connection_t *, self, 0)

  // Closing twice is what the module's own "double close" test does, and the
  // second call must not reach libutp with a pointer that is gone.
  if (utp_napi_connection_gone(self)) return NULL;

  utp_close(self->socket);

  return NULL;
}

NAPI_METHOD(utp_napi_connect) {
  NAPI_ARGV(4)
  UTP_NAPI_ARGV_SELF(utp_napi_t *, self, 0)
  UTP_NAPI_ARGV_SELF(utp_napi_connection_t *, conn, 1)
  NAPI_ARGV_UINT32(port, 2)
  NAPI_ARGV_UTF8(ip, UTP_NAPI_IP_MAX, 3)

  int err;
  struct sockaddr_storage addr;

  // The address is parsed BEFORE a socket exists. In the original order the
  // socket was created and given its userdata first, so an address that could
  // not be parsed left a socket created, registered and abandoned, with nothing
  // that would ever connect or close it. libutp then destroys it on its own
  // schedule, which is the callback path the crash of 2026-08-26 came down.
  err = utp_napi_addr_from_text((char *) &ip, port, &addr);
  if (err) UTP_NAPI_THROW(err)

  utp_napi_addr_for_socket(self->family, &addr);

  conn->socket = utp_create_socket(self->utp);
  if (conn->socket == NULL) UTP_NAPI_THROW(UV_ENOMEM)

  utp_set_userdata(conn->socket, conn);

  utp_connect(conn->socket, (struct sockaddr *) &addr, utp_napi_addr_len((struct sockaddr *) &addr));

  return NULL;
}

NAPI_INIT() {
  NAPI_EXPORT_FUNCTION(utp_napi_alloc)
  NAPI_EXPORT_FUNCTION(utp_napi_connection_alloc)
  NAPI_EXPORT_FUNCTION(utp_napi_send_request_alloc)
  NAPI_EXPORT_FUNCTION(utp_napi_set_accept_connections)
  NAPI_EXPORT_FUNCTION(utp_napi_connection_set_min_recv_packet_size)
  NAPI_EXPORT_FUNCTION(utp_napi_init)
  NAPI_EXPORT_FUNCTION(utp_napi_bind)
  NAPI_EXPORT_FUNCTION(utp_napi_local_port)
  NAPI_EXPORT_FUNCTION(utp_napi_send_request_init)
  NAPI_EXPORT_FUNCTION(utp_napi_send)
  NAPI_EXPORT_FUNCTION(utp_napi_close)
  NAPI_EXPORT_FUNCTION(utp_napi_destroy)
  NAPI_EXPORT_FUNCTION(utp_napi_ref)
  NAPI_EXPORT_FUNCTION(utp_napi_unref)
  NAPI_EXPORT_FUNCTION(utp_napi_set_ttl)
  NAPI_EXPORT_FUNCTION(utp_napi_send_buffer)
  NAPI_EXPORT_FUNCTION(utp_napi_recv_buffer)
  NAPI_EXPORT_FUNCTION(utp_napi_connection_init)
  NAPI_EXPORT_FUNCTION(utp_napi_connection_write)
  NAPI_EXPORT_FUNCTION(utp_napi_connection_writev)
  NAPI_EXPORT_FUNCTION(utp_napi_connection_close)
  NAPI_EXPORT_FUNCTION(utp_napi_connection_shutdown)
  NAPI_EXPORT_FUNCTION(utp_napi_connection_on_close)
  NAPI_EXPORT_FUNCTION(utp_napi_connect)
}
