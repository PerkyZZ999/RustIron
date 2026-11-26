"""D-040 item 7 (W398): exec attempts from site PHP stay denied and audited.

W398 measured on a product host that the shipped rustiron_php module denies
each exec attempt from rustiron_php_t with an AVC record that carries the
site's category. The record exists because the module grants no execute
right beyond its entry point and hides no exec denial. These checks keep
both facts in the module source: a later `dontaudit` or exec grant for the
site PHP domain fails here before it reaches a host.

D-048 (W401): the module hides exactly the benign denials that W398 counted
in normal WordPress traffic (refused name-lookup file reads, a statfs, and
an access(2) write check) and nothing else. The checks below pin that set:
a wider rule, a dontaudit interface, or a grant of the hidden access fails.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
PHP_TE = ROOT / "lab/s03/selinux/rustiron_php.te"
EXEC_PERMS = ("execute", "execute_no_trans", "entrypoint", "execmod")
# Reference-policy interfaces that grant exec, a transition or a shell.
EXEC_INTERFACES = (
    "can_exec", "domtrans_pattern", "domain_auto_trans", "spec_domtrans_pattern",
    "corecmd_exec_bin", "corecmd_exec_shell", "corecmd_exec_all_executables",
    "corecmd_shell_entry_type", "exec_files_pattern",
)
ENTRY_POINT = "init_daemon_domain(rustiron_php_t, rustiron_php_exec_t)"
# Every (target type, class, permission) that rustiron_php_t may hide.
# D-034: the ioctl on the render unit's output descriptor. D-048: the read
# and getattr of /etc/resolv.conf and /etc/hosts (D-019 keeps them denied),
# the statfs of / from site health, and the access(2) write check on the
# site's code folder (audit_access hides only access(2); a real write stays
# audited).
HIDDEN = {
    ("rustiron_admin_run_t", "file", "ioctl"),
    ("net_conf_t", "file", "getattr"),
    ("net_conf_t", "file", "read"),
    ("fs_t", "filesystem", "getattr"),
    ("httpd_sys_content_t", "dir", "audit_access"),
}
# The hidden access stays denied: no grant of these types to rustiron_php_t.
HIDDEN_DENIED = ("net_conf_t", "fs_t")
DONTAUDIT = re.compile(r"^dontaudit\s+rustiron_php_t\s+(\w+):(\w+)\s+(\{[\w\s]+\}|\w+)\s*;$")


def rules(text):
    """The module's statements, without comments, one per list item."""
    lines = (line.split("#", 1)[0].strip() for line in text.splitlines())
    return [line for line in lines if line]


def violations(statements):
    """Statements that would hide or grant an exec by rustiron_php_t."""
    found = []
    for line in statements:
        rule = re.match(r"^(allow|dontaudit)\s+rustiron_php_t\b", line)
        if rule and any(re.search(rf"\b{perm}\b", line) for perm in EXEC_PERMS):
            found.append(line)
        call = re.match(r"^(\w+)\(\s*rustiron_php_t\b", line)
        if call and call.group(1) in EXEC_INTERFACES:
            found.append(line)
    if ENTRY_POINT not in statements:
        found.append("missing " + ENTRY_POINT)
    return found


def hidden(statements):
    """The (type, class, permission) set that rustiron_php_t hides, and the
    statements that hide or grant beyond the reviewed D-048 bound."""
    found, extra = set(), []
    for line in statements:
        if re.match(r"^dontaudit\s+rustiron_php_t\b", line):
            rule = DONTAUDIT.match(line)
            if not rule:
                extra.append(line)  # a type set: not reviewed
                continue
            perms = rule.group(3).strip("{} ").split()
            found.update((rule.group(1), rule.group(2), perm) for perm in perms)
        elif re.match(r"^\w*dontaudit\w*\(\s*rustiron_php_t\b", line):
            extra.append(line)  # an interface hides an unreviewed set
        elif re.match(r"^sysnet_\w+\(\s*rustiron_php_t\b", line):
            extra.append(line)  # D-019: no name resolution for site PHP
        elif re.match(r"^allow\s+rustiron_php_t\s+(%s):" % "|".join(HIDDEN_DENIED), line):
            extra.append(line)
    return found, extra


class PhpExecAuditTests(unittest.TestCase):
    def test_site_php_exec_is_neither_granted_nor_hidden(self):
        self.assertEqual(violations(rules(PHP_TE.read_text())), [])

    def test_a_hidden_or_granted_exec_is_found(self):
        base = rules(PHP_TE.read_text())
        for bad in (
            "dontaudit rustiron_php_t bin_t:file execute;",
            "dontaudit rustiron_php_t shell_exec_t:file { execute execute_no_trans };",
            "dontaudit rustiron_php_t exec_type:file { getattr execute };",
            "allow rustiron_php_t httpd_sys_rw_content_t:file { read execute };",
            "corecmd_exec_shell(rustiron_php_t)",
            "can_exec(rustiron_php_t, bin_t)",
        ):
            self.assertEqual(violations(base + [bad]), [bad], bad)
        # Rules of the other domain in the module are not the PHP domain's.
        self.assertEqual(violations(base + ["corecmd_exec_bin(rustiron_unpack_t)"]), [])


class PhpDenialNoiseTests(unittest.TestCase):
    def test_hidden_denials_are_exactly_the_reviewed_set(self):
        self.assertEqual(hidden(rules(PHP_TE.read_text())), (HIDDEN, []))

    def test_a_wider_hidden_set_or_a_grant_is_found(self):
        base = rules(PHP_TE.read_text())
        for bad in (
            "dontaudit rustiron_php_t net_conf_t:file { getattr open read ioctl };",
            "dontaudit rustiron_php_t httpd_sys_content_t:dir write;",
            "dontaudit rustiron_php_t httpd_sys_rw_content_t:dir audit_access;",
            "dontaudit rustiron_php_t fs_t:filesystem { getattr mount };",
            "dontaudit rustiron_php_t self:udp_socket name_connect;",
            "dontaudit rustiron_php_t file_type:file read;",  # an attribute
        ):
            found, extra = hidden(base + [bad])
            self.assertNotEqual(found, hidden(base)[0], bad)
            self.assertFalse(found <= HIDDEN, bad)
            self.assertEqual(extra, [], bad)
        for bad in (
            "dontaudit rustiron_php_t { net_conf_t etc_t }:file read;",
            "sysnet_dontaudit_read_config(rustiron_php_t)",
            "files_dontaudit_search_all_dirs(rustiron_php_t)",
            "sysnet_read_config(rustiron_php_t)",
            "sysnet_dns_name_resolve(rustiron_php_t)",
            "allow rustiron_php_t net_conf_t:file read_file_perms;",
            "allow rustiron_php_t fs_t:filesystem getattr;",
        ):
            self.assertEqual(hidden(base + [bad])[1], [bad], bad)
        # Rules of the other domain in the module are not the PHP domain's.
        self.assertEqual(hidden(base + ["dontaudit rustiron_unpack_t net_conf_t:file read;"]), hidden(base))


if __name__ == "__main__":
    unittest.main()
