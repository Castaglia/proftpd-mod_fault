/*
 * ProFTPD: mod_fault -- a module for fault injection
 * Copyright (c) 2022 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_fault, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"

#define MOD_FAULT_VERSION		"mod_fault/0.0"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030001
# error "ProFTPD 1.3.0rc1 or later required"
#endif

module fault_module;

static int fault_engine = FALSE;

static pool *fault_pool = NULL;
static pr_table_t *fault_fsio_errtab = NULL;

struct fault_error {
  const char *error_name;
  int error_code;
};

static struct fault_error fault_errors[] = {
  { "EACCES",	EACCES },
  { "EAGAIN",	EAGAIN },
  { "EBADF",	EBADF },
#if defined(EBUSY)
  { "EBUSY",	EBUSY },
#endif /* EBUSY */
#if defined(EDQUOT)
  { "EDQUOT",	EDQUOT },
#endif /* EDQUOT */
  { "EEXIST",	EEXIST },
#if defined(EFBIG)
  { "EFBIG",	EFBIG },
#endif /* EFBIG */
  { "EIO",	EIO },
  { "EINTR",	EINTR },
#if defined(EMFILE)
  { "EMFILE",	EMFILE },
#endif /* EMFILE */
#if defined(ENFILE)
#if defined(EMLINK)
  { "EMLINK",	EMLINK },
#endif /* EMLINK */
  { "ENFILE",	ENFILE },
#endif /* ENFILE */
#if defined(ENODEV)
  { "ENODEV",	ENODEV },
#endif /* ENODEV */
  { "ENOENT",	ENOENT },
  { "ENOMEM",	ENOMEM },
  { "ENOSPC",	ENOSPC },
#if defined(ENOTEMPTY)
  { "ENOTEMPTY", ENOTEMPTY },
#endif /* ENOTEMPTY */
#if defined(ENXIO)
  { "ENXIO",	ENXIO },
#endif /* ENXIO */
#if defined(EOPNOTSUPP)
  { "EOPNOTSUPP", EOPNOTSUPP },
#endif /* EOPNOTSUPP */
  { "EPERM",	EPERM },
#if defined(EROFS)
  { "EROFS",	EROFS },
#endif /* EROFS */
#if defined(ESTALE)
  { "ESTALE",	ESTALE },
#endif /* ESTALE */
#if defined(ETXTBUSY)
  { "ETXTBUSY",	ETXTBUSY },
#endif /* ETXTBUSY */
  { NULL, -1 }
};

/* Note that the following FSO operations are deliberately omitted:
 *
 *  fstat
 *  lstat
 *  open
 *  stat
 *
 * Why?  These operations are fundamental to much of ProFTPD operations,
 * and injecting errors into these will cause unexpected other issues.
 * So at the moment, they are omitted.
 */
static const char *fault_fsio_operations[] = {
  "chmod",
  "chown",
  "chroot",
  "close",
  "closedir",
  "fchmod",
  "fchown",
  "lchown",
  "lseek",
  "mkdir",
  "opendir",
  "read",
  "readdir",
  "readlink",
  "rename",
  "rmdir",
  "write",
  "unlink",
  "utimes",
  NULL
};

static const char *trace_channel = "fault";

static const char *fault_errno2text(int xerrno) {
  register unsigned int i;

  for (i = 0; fault_errors[i].error_name != NULL; i++) {
    if (xerrno == fault_errors[i].error_code) {
      return fault_errors[i].error_name;
    }
  }

  errno = ENOENT;
  return NULL;
}

static int fault_text2errno(const char *text) {
  register unsigned int i;

  for (i = 0; fault_errors[i].error_name != NULL; i++) {
    if (strcasecmp(text, fault_errors[i].error_name) == 0) {
      return fault_errors[i].error_code;
    }
  }

  return -1;
}

static int fault_get_errno(pr_table_t *tab, const char *oper, int *xerrno) {
  const void *val = NULL;

  val = pr_table_get(tab, oper, NULL);
  if (val == NULL) {
    return -1;
  }

  *xerrno = *((int *) val);
  return 0;
}

static int supported_fsio_operation(const char *oper) {
  register unsigned int i;

  for (i = 0; fault_fsio_operations[i] != NULL; i++) {
    if (strcasecmp(fault_fsio_operations[i], oper) == 0) {
      return 0;
    }
  }

  return -1;
}

static int fault_error_dump(const void *key_data, size_t keysz,
    const void *val_data, size_t valsz, void *user_data) {
  int xerrno;

  xerrno = *((int *) val_data);
  pr_trace_msg(trace_channel, 20, "  %.*s: %s (%d) [%s]", (int) keysz,
    key_data, fault_errno2text(xerrno), xerrno, strerror(xerrno));
  return 0;
}

static void fault_tab_dump(pr_table_t *tab) {
  (void) pr_table_do(tab, fault_error_dump, NULL, PR_TABLE_DO_FL_ALL);
}

/* FSIO handlers
 */

/* TODO: Rather than defaulting the real system calls, should default to
 * the underlying FSIO module, thus honoring stacking.  In most cases,
 * that underlying FSIO module WILL be "core", i.e. the real system call.
 */

static int fault_fsio_chmod(pr_fs_t *fs, const char *path, mode_t mode) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "chmod", &xerrno) < 0) {
    return chmod(path, mode);
  }

  pr_trace_msg(trace_channel, 4, "fsio: chmod '%s', returning %s (%s)", path,
    fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static int fault_fsio_chown(pr_fs_t *fs, const char *path, uid_t uid,
    gid_t gid) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "chown", &xerrno) < 0) {
    return chown(path, uid, gid);
  }

  pr_trace_msg(trace_channel, 4, "fsio: chown '%s', returning %s (%s)", path,
    fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static int fault_fsio_chroot(pr_fs_t *fs, const char *path) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "chroot", &xerrno) < 0) {
    int res;

    res = chroot(path);
    if (res >= 0) {
      /* Note: Ideally this assignment wouldn't be in an FSIO callback... */
      session.chroot_path = (char *) path;
    }

    return res;
  }

  pr_trace_msg(trace_channel, 4, "fsio: chroot '%s', returning %s (%s)", path,
    fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static int fault_fsio_close(pr_fh_t *fh, int fd) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "close", &xerrno) < 0) {
    return close(fd);
  }

  pr_trace_msg(trace_channel, 4, "fsio: close %d ('%s'), returning %s (%s)", fd,
    fh->fh_path, fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static int fault_fsio_closedir(pr_fs_t *fs, void *dirh) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "closedir", &xerrno) < 0) {
    return closedir((DIR *) dirh);
  }

  pr_trace_msg(trace_channel, 4, "fsio: closedir, returning %s (%s)",
    fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static int fault_fsio_fchmod(pr_fh_t *fh, int fd, mode_t mode) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "chmod", &xerrno) < 0) {
    return fchmod(fd, mode);
  }

  pr_trace_msg(trace_channel, 4, "fsio: fchmod %d ('%s'), returning %s (%s)",
    fd, fh->fh_path, fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static int fault_fsio_fchown(pr_fh_t *fh, int fd, uid_t uid, gid_t gid) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "chown", &xerrno) < 0) {
    return fchown(fd, uid, gid);
  }

  pr_trace_msg(trace_channel, 4, "fsio: fchown %d ('%s'), returning %s (%s)",
    fd, fh->fh_path, fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static int fault_fsio_futimes(pr_fh_t *fh, int fd, struct timeval *tvs) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "utimes", &xerrno) < 0) {
#if defined(HAVE_FUTIMES)
    int res;

    res = futimes(fd, tvs);
    if (res < 0 &&
        errno == ENOSYS) {
      return utimes(fh->fh_path, tvs);
    }

    return res;
#else
    return utimes(fh->fh_path, tvs);
#endif /* HAVE_FUTIMES */
  }

  pr_trace_msg(trace_channel, 4, "fsio: futimes (%d) '%s', returning %s (%s)",
    fd, fh->fh_path, fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static int fault_fsio_lchown(pr_fs_t *fs, const char *path, uid_t uid,
    gid_t gid) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "chown", &xerrno) < 0) {
    return lchown(path, uid, gid);
  }

  pr_trace_msg(trace_channel, 4, "fsio: lchown '%s', returning %s (%s)", path,
    fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static off_t fault_fsio_lseek(pr_fh_t *fh, int fd, off_t offset, int whence) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "lseek", &xerrno) < 0) {
    return lseek(fd, offset, whence);
  }

  pr_trace_msg(trace_channel, 4, "fsio: lseek %d ('%s'), returning %s (%s)", fd,
    fh->fh_path, fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static int fault_fsio_mkdir(pr_fs_t *fs, const char *path, mode_t mode) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "mkdir", &xerrno) < 0) {
    return mkdir(path, mode);
  }

  pr_trace_msg(trace_channel, 4, "fsio: mkdir '%s', returning %s (%s)", path,
    fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static void *fault_fsio_opendir(pr_fs_t *fs, const char *path) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "opendir", &xerrno) < 0) {
    return opendir(path);
  }

  pr_trace_msg(trace_channel, 4, "fsio: opendir '%s', returning %s (%s)", path,
    fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return NULL;
}

static ssize_t fault_fsio_pread(pr_fh_t *fh, int fd, void *buf, size_t bufsz,
    off_t offset) {
  int xerrno = 0;

  /* For fault injection purposes, we treat `pread(2)` just like `read(2)`. */
  if (fault_get_errno(fault_fsio_errtab, "read", &xerrno) < 0) {
#if defined(HAVE_PREAD)
    return pread(fd, buf, bufsz, offset);
#else
    errno = ENOSYS;
    return -1;
#endif /* HAVE_PREAD */
  }

  pr_trace_msg(trace_channel, 4,
    "fsio: pread %d ('%s', %lu bytes, %" PR_LU " offset), returning %s (%s)",
    fd, fh->fh_path, (unsigned long) bufsz, (pr_off_t) offset,
    fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static ssize_t fault_fsio_pwrite(pr_fh_t *fh, int fd, const void *buf,
    size_t bufsz, off_t offset) {
  int xerrno = 0;

  /* For fault injection purposes, we treat `pwrite(2)` just like `write(2)`. */
  if (fault_get_errno(fault_fsio_errtab, "write", &xerrno) < 0) {
#if defined(HAVE_PWRITE)
    return pwrite(fd, buf, bufsz, offset);
#else
    errno = ENOSYS;
    return -1;
#endif /* HAVE_PWRITE */
  }

  pr_trace_msg(trace_channel, 4,
    "fsio: pwrite %d ('%s', %lu bytes, %" PR_LU " offset), returning %s (%s)",
    fd, fh->fh_path, (unsigned long) bufsz, (pr_off_t) offset,
    fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static int fault_fsio_read(pr_fh_t *fh, int fd, char *buf, size_t bufsz) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "read", &xerrno) < 0) {
    return read(fd, buf, bufsz);
  }

  pr_trace_msg(trace_channel, 4,
    "fsio: read %d ('%s', %lu bytes), returning %s (%s)", fd, fh->fh_path,
    (unsigned long) bufsz, fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static struct dirent *fault_fsio_readdir(pr_fs_t *fs, void *dirh) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "readdir", &xerrno) < 0) {
    return readdir((DIR *) dirh);
  }

  pr_trace_msg(trace_channel, 4, "fsio: readdir, returning %s (%s)",
    fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return NULL;
}

static int fault_fsio_readlink(pr_fs_t *fs, const char *path, char *buf,
    size_t bufsz) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "readlink", &xerrno) < 0) {
    return readlink(path, buf, bufsz);
  }

  pr_trace_msg(trace_channel, 4, "fsio: readlink '%s', returning %s (%s)", path,
    fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static int fault_fsio_rename(pr_fs_t *fs, const char *src_path,
    const char *dst_path) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "rename", &xerrno) < 0) {
    return rename(src_path, dst_path);
  }

  pr_trace_msg(trace_channel, 4, "fsio: rename '%s' to '%s', returning %s (%s)",
    src_path, dst_path, fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static int fault_fsio_rmdir(pr_fs_t *fs, const char *path) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "rmdir", &xerrno) < 0) {
    return rmdir(path);
  }

  pr_trace_msg(trace_channel, 4, "fsio: rmdir '%s', returning %s (%s)", path,
    fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static int fault_fsio_write(pr_fh_t *fh, int fd, const char *buf,
    size_t bufsz) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "write", &xerrno) < 0) {
    return write(fd, buf, bufsz);
  }

  pr_trace_msg(trace_channel, 4,
    "fsio: write %d ('%s', %lu bytes), returning %s (%s)", fd, fh->fh_path,
    (unsigned long) bufsz, fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static int fault_fsio_unlink(pr_fs_t *fs, const char *path) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "unlink", &xerrno) < 0) {
    return unlink(path);
  }

  pr_trace_msg(trace_channel, 4, "fsio: unlink '%s', returning %s (%s)", path,
    fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

static int fault_fsio_utimes(pr_fs_t *fs, const char *path,
    struct timeval *tvs) {
  int xerrno = 0;

  if (fault_get_errno(fault_fsio_errtab, "utimes", &xerrno) < 0) {
    return utimes(path, tvs);
  }

  pr_trace_msg(trace_channel, 4, "fsio: utimes '%s', returning %s (%s)", path,
    fault_errno2text(xerrno), strerror(xerrno));
  errno = xerrno;
  return -1;
}

/* Configuration handlers
 */

/* usage: FaultEngine on|off */
MODRET set_faultengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: FaultInject category error oper1 ... */
MODRET set_faultinject(cmd_rec *cmd) {
  register unsigned int i;
  const char *error_category, *error_text;
  int xerrno;

  if (cmd->argc < 4) {
    CONF_ERROR(cmd, "missing parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT);

  error_category = cmd->argv[1];

  /* Note that this category allows for future APIs/errors, such as NetIO. */
  if (strcasecmp(error_category, "filesystem") != 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unsupported category: ",
      error_category, NULL));
  }

  error_text = cmd->argv[2];
  xerrno = fault_text2errno(error_text);
  if (xerrno < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown/unsupported error: ",
      error_text, NULL));
  }

  for (i = 3; i < cmd->argc; i++) {
    const char *oper;

    oper = cmd->argv[i];

    if (supported_fsio_operation(oper) < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "unknown/unsupported ", error_category, " operation: ", oper, NULL));
    }

    if (pr_table_exists(fault_fsio_errtab, oper) > 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, error_category,
        " configuration already exists for '", oper, "'", NULL));
    }

    /* Note that the table API copies the key pointer as is, thus we
     * need to use a key pointer of a longer lifetime than this parsing
     * record pool.
     */
    if (pr_table_add_dup(fault_fsio_errtab, pstrdup(fault_pool, oper),
        &xerrno, sizeof(int)) < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "error configuring ", error_category, " fault injection for '", oper,
        "': ", strerror(errno), NULL));
    }
  }

  return PR_HANDLED(cmd);
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void fault_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_fault.c", (const char *) event_data) != 0) {
    return;
  }

  (void) pr_unmount_fs("/", "fault");
  pr_event_unregister(&fault_module, NULL, NULL);

  destroy_pool(fault_pool);
  fault_pool = NULL;
  fault_fsio_errtab = NULL;
  fault_engine = FALSE;
}
#endif /* PR_SHARED_MODULE */

static void fault_restart_ev(const void *event_data, void *user_data) {
  if (fault_pool != NULL) {
    destroy_pool(fault_pool);
  }

  fault_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(fault_pool, MOD_FAULT_VERSION);

  fault_fsio_errtab = pr_table_alloc(fault_pool, 0);
}

/* Initialization functions
 */

static int fault_init(void) {
#if defined(PR_SHARED_MODULE)
  pr_event_register(&fault_module, "core.module-unload", fault_mod_unload_ev,
    NULL);
#endif /* PR_SHARED_MODULE */

  pr_event_register(&fault_module, "core.restart", fault_restart_ev, NULL);

  fault_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(fault_pool, MOD_FAULT_VERSION);

  fault_fsio_errtab = pr_table_alloc(fault_pool, 0);
  return 0;
}

/* For now, we only inject faults for session processes, NOT for the daemon
 * process.
 */
static int fault_sess_init(void) {
  config_rec *c;
  int fsio_fault_count;

  c = find_config(main_server->conf, CONF_PARAM, "FaultEngine", FALSE);
  if (c == NULL) {
    return 0;
  }

  fault_engine = *((int *) c->argv[0]);
  if (fault_engine == FALSE) {
    return 0;
  }

  fsio_fault_count = pr_table_count(fault_fsio_errtab);
  if (fsio_fault_count > 0) {
    pr_fs_t *fs;

    pr_trace_msg(trace_channel, 7,
      "filesystem fault injections (%d) configured, registering custom FS",
      fsio_fault_count);

    if (pr_trace_get_level(trace_channel) >= 20) {
      fault_tab_dump(fault_fsio_errtab);
    }

    /* Register our custom filesystem. */
    fs = pr_register_fs(session.pool, "fault", "/");
    if (fs != NULL) {
      fs->chmod = fault_fsio_chmod;
      fs->chown = fault_fsio_chown;
      fs->chroot = fault_fsio_chroot;
      fs->close = fault_fsio_close;
      fs->closedir = fault_fsio_closedir;
      fs->fchmod = fault_fsio_fchmod;
      fs->fchown = fault_fsio_fchown;
      fs->futimes = fault_fsio_futimes;
      fs->lchown = fault_fsio_lchown;
      fs->lseek = fault_fsio_lseek;
      fs->mkdir = fault_fsio_mkdir;
      fs->opendir = fault_fsio_opendir;
      fs->pread = fault_fsio_pread;
      fs->pwrite = fault_fsio_pwrite;
      fs->read = fault_fsio_read;
      fs->readdir = fault_fsio_readdir;
      fs->readlink = fault_fsio_readlink;
      fs->rename = fault_fsio_rename;
      fs->rmdir = fault_fsio_rmdir;
      fs->write = fault_fsio_write;
      fs->unlink = fault_fsio_unlink;
      fs->utimes = fault_fsio_utimes;
    }
  }

  return 0;
}

/* Module API tables
 */

static conftable fault_conftab[] = {
  { "FaultEngine",		set_faultengine,	NULL },
  { "FaultInject",		set_faultinject,	NULL },
  { NULL }
};

module fault_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "fault",

  /* Module configuration handler table */
  fault_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  fault_init,

  /* Session initialization function */
  fault_sess_init,

  /* Module version */
  MOD_FAULT_VERSION
};
