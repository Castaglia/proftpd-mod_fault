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

static const char *fault_fsio_operations[] = {
  "chmod",
  "chown",
  "chroot",
  "close",
  "closedir",
  "mkdir",
  "open",
  "opendir",
  "read",
  "readdir",
  "rename",
  "rmdir",
  "write",
  "unlink",
  NULL
};

static const char *trace_channel = "fault";

static const char *fault_errno2text(int xerrno) {
  const char *text = NULL;

  switch (xerrno) {
    case EACCES:
      text = "EACCES";
      break;

    case EAGAIN:
      text = "EAGAIN";
      break;

    case EBADF:
      text = "EBADF";
      break;

#if defined(EBUSY)
    case EBUSY:
      text = "EBUSY";
      break;
#endif /* EBUSY */

#if defined(EDQUOT)
    case EDQUOT:
      text = "EDQUOT";
      break;
#endif /* EDQUOT */

    case EEXIST:
      text = "ENOSPC";
      break;

    case ENOSPC:
      text = "ENOSPC";
      break;

    default:
      errno = ENOENT;
      text = NULL;
  }

  return text;
}

static int fault_text2errno(const char *text) {
  if (strcasecmp(text, "EACCES") == 0) {
    return EACCES;
  }

  if (strcasecmp(text, "EAGAIN") == 0) {
    return EAGAIN;
  }

  if (strcasecmp(text, "EBADF") == 0) {
    return EBADF;
  }

#if defined(EBUSY)
  if (strcasecmp(text, "EBUSY") == 0) {
    return EBUSY;
  }
#endif /* EBUSY */

#if defined(EDQUOT)
  if (strcasecmp(text, "EDQUOT") == 0) {
    return EDQUOT;
  }
#endif /* EDQUOT */

  if (strcasecmp(text, "EEXIST") == 0) {
    return EEXIST;
  }

  if (strcasecmp(text, "ENOSPC") == 0) {
    return ENOSPC;
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
      fs->close = fault_fsio_close;
      fs->mkdir = fault_fsio_mkdir;
      fs->pwrite = fault_fsio_pwrite;
      fs->rename = fault_fsio_rename;
      fs->write = fault_fsio_write;
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
