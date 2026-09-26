/*
 * module_crc_bypass.c - bypass CRC/vermagic checks for module loading
 *
 * Hooks load_module() and forces MODULE_INIT_IGNORE_MODVERSIONS
 * and MODULE_INIT_IGNORE_VERMAGIC flags.
 *
 * SPDX-License-Identifier: GPL-3.0
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <asm-generic/rwonce.h>
#include <uapi/asm-generic/errno.h>
#include <ksyms.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>

#ifndef MODULE_CRC_BYPASS_VERSION
#define MODULE_CRC_BYPASS_VERSION "1.0.0"
#endif

/* Flags de load_module */
#define MODULE_INIT_IGNORE_MODVERSIONS 0x0002
#define MODULE_INIT_IGNORE_VERMAGIC    0x0004

/* Dirección de load_module (obtenida del vmlinux.elf) */
#define LOAD_MODULE_ADDR 0xffffffc01038f588UL

KPM_NAME("module_crc_bypass");
KPM_VERSION(MODULE_CRC_BYPASS_VERSION);
KPM_LICENSE("GPLv3");
KPM_AUTHOR("juancamilocastaneda85");
KPM_DESCRIPTION("Bypass CRC/vermagic checks for module loading");

static void *g_load_module;
static bool g_hook_installed;
static bool g_enabled = true;
static unsigned long g_load_calls;
static unsigned long g_bypasses;

static size_t local_strlen(const char *s)
{
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static bool command_is(const char *args, const char *expected)
{
    size_t i = 0;
    size_t expected_len = local_strlen(expected);
    if (!args || !expected) return false;
    while (*args == ' ' || *args == '\t') args++;
    while (i < expected_len && args[i] == expected[i]) i++;
    if (i != expected_len) return false;
    while (args[i] == ' ' || args[i] == '\t' ||
           args[i] == '\r' || args[i] == '\n') i++;
    return args[i] == '\0';
}

/*
 * load_module(const char *name, struct load_info *info, u32 flags)
 *
 * Argumentos:
 *   arg0 = name (const char *)
 *   arg1 = info (struct load_info *)
 *   arg2 = flags (u32)
 */
static void before_load_module(hook_fargs8_t *a, void *udata)
{
    u32 flags;
    
    (void)udata;
    
    WRITE_ONCE(g_load_calls, READ_ONCE(g_load_calls) + 1);
    
    if (!READ_ONCE(g_enabled))
        return;
    
    flags = (u32)a->arg2;
    
    /* Forzar ignore modversions + vermagic */
    a->arg2 = flags | MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC;
    
    if (flags != a->arg2) {
        WRITE_ONCE(g_bypasses, READ_ONCE(g_bypasses) + 1);
        pr_info("[module_crc_bypass] forced ignore CRC+vermagic (flags 0x%x -> 0x%x)\n",
                flags, (u32)a->arg2);
    }
}

static void copy_status_to_user(char __user *out_msg, int outlen, char *buf)
{
    size_t copy_len;
    if (!out_msg || outlen <= 0) return;
    copy_len = local_strlen(buf) + 1;
    if (copy_len > (size_t)outlen) {
        copy_len = (size_t)outlen;
        buf[copy_len - 1] = '\0';
    }
    compat_copy_to_user(out_msg, buf, copy_len);
}

static long control(const char *args, char __user *out_msg, int outlen)
{
    char buf[256];
    
    if (command_is(args, "enable")) {
        WRITE_ONCE(g_enabled, true);
        snprintf(buf, sizeof(buf),
                 "enabled: CRC/vermagic bypass active\n");
    } else if (command_is(args, "disable")) {
        WRITE_ONCE(g_enabled, false);
        snprintf(buf, sizeof(buf),
                 "disabled: CRC/vermagic checks restored\n");
    } else if (command_is(args, "reset")) {
        WRITE_ONCE(g_load_calls, 0);
        WRITE_ONCE(g_bypasses, 0);
        snprintf(buf, sizeof(buf), "counters reset\n");
    } else {
        snprintf(buf, sizeof(buf),
                 "v%s enabled=%u hook=%u load_calls=%lu bypasses=%lu "
                 "load_module=%px\n",
                 MODULE_CRC_BYPASS_VERSION,
                 READ_ONCE(g_enabled) ? 1U : 0U,
                 READ_ONCE(g_hook_installed) ? 1U : 0U,
                 READ_ONCE(g_load_calls),
                 READ_ONCE(g_bypasses),
                 g_load_module);
    }
    
    pr_info("[module_crc_bypass] ctl: %s", buf);
    copy_status_to_user(out_msg, outlen, buf);
    return 0;
}

static long init(const char *args, const char *event, void *__user reserved)
{
    hook_err_t rc;
    
    (void)args;
    (void)reserved;
    
    pr_info("[module_crc_bypass] init event=%s v%s\n",
            event ? event : "(null)", MODULE_CRC_BYPASS_VERSION);
    
    /* Buscar load_module por nombre primero */
    g_load_module = (void *)kallsyms_lookup_name("load_module");
    
    /* Si no lo encuentra, usar dirección directa */
    if (!g_load_module) {
        pr_warn("[module_crc_bypass] kallsyms_lookup_name failed, using hardcoded address\n");
        g_load_module = (void *)LOAD_MODULE_ADDR;
    }
    
    if (!g_load_module) {
        pr_err("[module_crc_bypass] load_module unavailable\n");
        return -ENOENT;
    }
    
    pr_info("[module_crc_bypass] load_module=%px, installing hook...\n", g_load_module);
    
    rc = hook_wrap8(g_load_module, before_load_module, NULL, NULL);
    if (rc != HOOK_NO_ERR) {
        pr_err("[module_crc_bypass] hook_wrap8 failed: %d\n", rc);
        g_load_module = NULL;
        return -(long)rc;
    }
    
    WRITE_ONCE(g_hook_installed, true);
    WRITE_ONCE(g_enabled, true);
    
    pr_info("[module_crc_bypass] active: hook installed at %px\n", g_load_module);
    return 0;
}

static long exit_(void *__user reserved)
{
    (void)reserved;
    
    WRITE_ONCE(g_enabled, false);
    
    if (READ_ONCE(g_hook_installed) && g_load_module) {
        hook_unwrap(g_load_module, before_load_module, NULL);
        WRITE_ONCE(g_hook_installed, false);
    }
    
    pr_info("[module_crc_bypass] exit: load_calls=%lu bypasses=%lu\n",
            READ_ONCE(g_load_calls), READ_ONCE(g_bypasses));
    
    g_load_module = NULL;
    return 0;
}

KPM_INIT(init);
KPM_CTL0(control);
KPM_EXIT(exit_);
