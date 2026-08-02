#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define SOCK_PATH "/data/local/tmp/temp_su.sock"

static void set_root_env(void) {
  setenv("PATH",
         "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:"
         "/apex/com.android.virt/bin:/system_ext/bin:/system/bin:/system/xbin:"
         "/odm/bin:/vendor/bin:/vendor/xbin",
         1);
  setenv("HOME", "/data/local/tmp", 1);
  setenv("USER", "root", 1);
  setenv("LOGNAME", "root", 1);
}

/*
 * Switch SELinux context before exec. We are spawned in u:r:kernel:s0
 * (inherited from the kernel context the exploit ran in). The kernel LSM
 * is permissive so kernel-side checks don't care, but userspace daemons
 * (init property_service, servicemanager) do their own
 * selinux_check_access() against raw policy, and stock policy has no
 * rules for the kernel domain: every setprop fails ("SELinux permission
 * check failed" from init) and every binder service lookup is denied.
 * The shell domain is what adb shell runs as — policy allows it
 * powerctl/debug props and service_manager access — and combined with
 * uid 0 that makes reboot/pm/setprop all work.
 *
 * The write to /proc/self/attr/current (task_setcurrent) is itself an
 * LSM check, allowed here because the kernel side is permissive.
 * Failures are non-fatal: we stay in the kernel context, exactly the
 * old behavior.
 *
 * ctx comes from the client (su --ctx <ctx> or $SU_SECTX); NULL/empty
 * picks the default. "-" or "none" skips the switch entirely (keeps the
 * kernel context).
 */
#define SU_SECTX_DEFAULT "u:r:shell:s0"
#define SU_SECTX_MAX 120

static void set_selinux_ctx(const char *ctx) {
  if (!ctx || !*ctx) {
    ctx = SU_SECTX_DEFAULT;
  }
  if (!strcmp(ctx, "-") || !strcmp(ctx, "none")) {
    return;
  }

  int fd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = write(fd, ctx, strlen(ctx));
  if (n < 0) {
    /* some kernels want a trailing newline */
    char buf[128];
    int len = snprintf(buf, sizeof(buf), "%s\n", ctx);
    lseek(fd, 0, SEEK_SET);
    n = write(fd, buf, (size_t)len);
  }
  close(fd);
  if (n < 0) {
    dprintf(STDERR_FILENO, "su: setcon %s failed: %s (staying in kernel ctx)\n",
            ctx, strerror(errno));
  }
}

static void xwrite(int fd, const void *buf, size_t len) {
  const char *p = (const char *)buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      _exit(111);
    }
    p += n;
    len -= (size_t)n;
  }
}

static int read_full(int fd, void *buf, size_t len) {
  char *p = (char *)buf;
  while (len) {
    ssize_t n = read(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static int connect_daemon(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("su: socket");
    return -1;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", SOCK_PATH);

  if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    perror("su: connect daemon");
    close(fd);
    return -1;
  }
  return fd;
}

/*
 * Deliver EOF to the peer of a closed input: shutdown() for a socket,
 * a literal ^D for a pty master (its line discipline turns it into EOF
 * for the shell reading the slave side).
 */
static void forward_eof(int fd, int is_pty) {
  if (is_pty) {
    char c = 0x04;
    ssize_t unused = write(fd, &c, 1);
    (void)unused;
  } else {
    shutdown(fd, SHUT_WR);
  }
}

static int pump_write(int fd, const void *buf, size_t len) {
  const char *p = (const char *)buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

/*
 * Pump bytes between a (input side) and b (output source).
 *
 * EOF on a is forwarded to b and we keep draining b -> a, so scripted
 * usage (stdin closing early) still receives the remaining output.
 * EOF/HUP on b means the peer is gone for good: return immediately
 * instead of waiting for a to EOF as well. Waiting for both (the old
 * behavior) is what hung the session: after the remote shell exited
 * (^D / `exit`), the pty master signalled EOF but the client's stdin
 * stayed open forever — and the local tty was left in raw mode, so the
 * calling shell looked completely dead.
 */
static int pump_pair(int a, int b, int b_is_pty) {
  char buf[4096];
  int a_open = 1;
  int b_open = 1;

  while (a_open || b_open) {
    struct pollfd pfd[2];
    int nfd = 0;
    if (a_open) {
      pfd[nfd].fd = a;
      pfd[nfd].events = POLLIN;
      nfd++;
    }
    if (b_open) {
      pfd[nfd].fd = b;
      pfd[nfd].events = POLLIN;
      nfd++;
    }

    int pr = poll(pfd, (nfds_t)nfd, -1);
    if (pr < 0 && errno == EINTR) {
      continue;
    }
    if (pr < 0) {
      return 1;
    }

    int idx = 0;
    if (a_open) {
      short re = pfd[idx++].revents;
      if (re & POLLIN) {
        ssize_t n = read(a, buf, sizeof(buf));
        if (n > 0) {
          if (!pump_write(b, buf, (size_t)n)) {
            return 0; /* peer died mid-write; nothing more to do */
          }
        } else {
          a_open = 0;
          forward_eof(b, b_is_pty);
        }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) {
        a_open = 0;
        forward_eof(b, b_is_pty);
      }
    }
    if (b_open) {
      short re = pfd[idx++].revents;
      if (re & POLLIN) {
        ssize_t n = read(b, buf, sizeof(buf));
        if (n > 0) {
          if (!pump_write(a, buf, (size_t)n)) {
            return 0;
          }
        } else {
          return 0; /* remote side finished — session over */
        }
      } else if (re & (POLLHUP | POLLERR | POLLNVAL)) {
        return 0;
      }
    }
  }
  return 0;
}

static struct termios g_saved_tio;
static int g_have_saved_tio;

static void restore_tty(void) {
  if (g_have_saved_tio) {
    tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_tio);
    g_have_saved_tio = 0;
  }
}

static void sig_restore_tty(int sig) {
  restore_tty();
  signal(sig, SIG_DFL);
  raise(sig);
}

static void send_ctx(int fd, const char *ctx) {
  uint16_t len = 0;
  if (ctx) {
    size_t l = strlen(ctx);
    len = (uint16_t)(l > SU_SECTX_MAX ? SU_SECTX_MAX : l);
  }
  xwrite(fd, &len, sizeof(len));
  if (len) {
    xwrite(fd, ctx, len);
  }
}

static int client_main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);

  const char *ctx = getenv("SU_SECTX");
  int i = 1;
  if (i + 1 < argc && strcmp(argv[i], "--ctx") == 0) {
    ctx = argv[i + 1];
    i += 2;
  }

  int fd = connect_daemon();
  if (fd < 0) {
    return 127;
  }

  if (i + 1 < argc && strcmp(argv[i], "-c") == 0) {
    char mode = 'C';
    uint32_t len = (uint32_t)strlen(argv[i + 1]);
    xwrite(fd, &mode, 1);
    send_ctx(fd, ctx);
    xwrite(fd, &len, sizeof(len));
    xwrite(fd, argv[i + 1], len);
    shutdown(fd, SHUT_WR);

    char buf[4096];
    for (;;) {
      ssize_t n = read(fd, buf, sizeof(buf));
      if (n < 0 && errno == EINTR) {
        continue;
      }
      if (n <= 0) {
        break;
      }
      xwrite(STDOUT_FILENO, buf, (size_t)n);
    }
    close(fd);
    return 0;
  }

  char mode = 'I';
  xwrite(fd, &mode, 1);
  send_ctx(fd, ctx);

  /*
   * Put the local tty into raw mode while pumping. Otherwise the
   * local line discipline echoes input AND line-buffers it, and the
   * remote pty echoes it a second time on the way back — every
   * command appears twice. With raw local mode the remote pty's
   * echo is the only one (and arrows/ctrl keys pass through).
   */
  struct termios saved;
  int raw_mode = 0;
  if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &saved) == 0) {
    struct termios raw = saved;
    cfmakeraw(&raw);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0) {
      raw_mode = 1;
      g_saved_tio = saved;
      g_have_saved_tio = 1;
      atexit(restore_tty);
      signal(SIGTERM, sig_restore_tty);
      signal(SIGHUP, sig_restore_tty);
      signal(SIGQUIT, sig_restore_tty);
    }
  }

  int rc = pump_pair(STDIN_FILENO, fd, 0);

  if (raw_mode) {
    tcsetattr(STDIN_FILENO, TCSANOW, &saved);
    g_have_saved_tio = 0;
  }
  close(fd);
  return rc;
}

static void exec_command_client(int conn, const char *cmd, const char *ctx) {
  pid_t pid = fork();
  if (pid == 0) {
    dup2(conn, STDIN_FILENO);
    dup2(conn, STDOUT_FILENO);
    dup2(conn, STDERR_FILENO);
    close(conn);
    set_root_env();
    // set_selinux_ctx(ctx);
    execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
    _exit(127);
  }

  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
}

static int open_pty_master(char *slave, size_t slave_len) {
  int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master < 0) {
    return -1;
  }
  if (grantpt(master) != 0 || unlockpt(master) != 0) {
    close(master);
    return -1;
  }
  if (ptsname_r(master, slave, slave_len) != 0) {
    close(master);
    return -1;
  }
  return master;
}

static void exec_interactive_client(int conn, const char *ctx) {
  char slave_name[128];
  int master = open_pty_master(slave_name, sizeof(slave_name));
  if (master < 0) {
    const char msg[] = "su daemon: failed to open pty\n";
    xwrite(conn, msg, sizeof(msg) - 1);
    return;
  }

  pid_t pid = fork();
  if (pid == 0) {
    setsid();
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) {
      _exit(126);
    }
    ioctl(slave, TIOCSCTTY, 0);
    dup2(slave, STDIN_FILENO);
    dup2(slave, STDOUT_FILENO);
    dup2(slave, STDERR_FILENO);
    if (slave > STDERR_FILENO) {
      close(slave);
    }
    close(master);
    close(conn);
    set_root_env();
    // set_selinux_ctx(ctx);
    execl("/system/bin/sh", "sh", "-i", (char *)NULL);
    _exit(127);
  }

  pump_pair(conn, master, 1);
  kill(pid, SIGHUP);
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  close(master);
}

static void serve_one(int conn) {
  /* daemon_main sets SIGCHLD to SIG_IGN (auto-reap); handlers need to
   * waitpid() their own exec child, so restore the default here. */
  signal(SIGCHLD, SIG_DFL);

  char mode = 0;
  if (!read_full(conn, &mode, 1)) {
    return;
  }

  uint16_t clen = 0;
  char ctx[SU_SECTX_MAX + 1];
  if (!read_full(conn, &clen, sizeof(clen)) || clen > SU_SECTX_MAX) {
    return;
  }
  if (clen && !read_full(conn, ctx, clen)) {
    return;
  }
  ctx[clen] = 0;
  const char *ctxp = clen ? ctx : NULL;

  if (mode == 'C') {
    uint32_t len = 0;
    if (!read_full(conn, &len, sizeof(len)) || len > 65536) {
      return;
    }
    char *cmd = calloc(1, (size_t)len + 1);
    if (!cmd) {
      return;
    }
    if (!read_full(conn, cmd, len)) {
      free(cmd);
      return;
    }
    exec_command_client(conn, cmd, ctxp);
    free(cmd);
  } else if (mode == 'I') {
    exec_interactive_client(conn, ctxp);
  }
}

static int daemon_main(void) {
  signal(SIGPIPE, SIG_IGN);
  /* auto-reap per-connection handlers; without this each finished
   * session leaves a zombie until the next accept(). */
  signal(SIGCHLD, SIG_IGN);
  set_root_env();

  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("socket");
    return 1;
  }

  unlink(SOCK_PATH);
  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", SOCK_PATH);

  if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    perror("bind");
    return 1;
  }
  chmod(SOCK_PATH, 0666);
  if (listen(fd, 16) != 0) {
    perror("listen");
    return 1;
  }

  fprintf(stderr, "su daemon ready pid=%d socket=%s uid=%d euid=%d\n",
          getpid(), SOCK_PATH, getuid(), geteuid());

  for (;;) {
    int conn = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if (conn < 0 && errno == EINTR) {
      continue;
    }
    if (conn < 0) {
      perror("accept");
      sleep(1);
      continue;
    }

    pid_t pid = fork();
    if (pid == 0) {
      close(fd);
      serve_one(conn);
      close(conn);
      _exit(0);
    }
    close(conn);
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
  }
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "--daemon") == 0) {
    return daemon_main();
  }
  return client_main(argc, argv);
}
