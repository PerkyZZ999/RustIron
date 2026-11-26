#!/bin/sh
# Build a private staging root on the AlmaLinux 10 target platform.
set -eu

if [ "$#" -ne 1 ] || [ ! -d "$1" ]; then
    echo 'Usage: packaging/stage-product.sh EXISTING_OUTPUT_PARENT' >&2
    exit 2
fi
if [ "$(id -u)" -eq 0 ]; then
    echo 'Build the staging root as an unprivileged user.' >&2
    exit 2
fi
. /etc/os-release
version=${VERSION_ID:-}
if [ "${ID:-}" != almalinux ] || [ "${version%%.*}" != 10 ] || [ "$(uname -m)" != x86_64 ]; then
    echo 'The product staging build requires AlmaLinux 10 x86_64.' >&2
    exit 2
fi

output=$(CDPATH= cd -- "$1" && pwd -P)
cd "$(dirname "$0")/.."
umask 077

python3 scripts/prepare_sqlite.py
unset CARGO_ENCODED_RUSTFLAGS
build=target/product-staging
RUSTFLAGS='--cfg rustiron_profile="product"' cargo build --release --locked --offline \
    --target-dir "$build" \
    --bin rustiron --bin rustiron-control --bin rustiron-s02-executor \
    --bin rustiron-admin-helper --bin rustiron-restore-inventory --bin rustiron-capture-manifest \
    --bin rustiron-migration-inventory

stage=$(mktemp -d "$output/rustiron-product.XXXXXXXX")
policy_build=
complete=no
cleanup() {
    if [ -n "$policy_build" ]; then rm -rf -- "$policy_build"; fi
    if [ "$complete" = no ]; then rm -rf -- "$stage"; fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
policy_build=$(mktemp -d)
cp policy/selinux/* lab/s03/selinux/rustiron_php.* "$policy_build/"
cat packaging/selinux/rustiron_site_root.fc >>"$policy_build/rustiron_admin.fc"
cp lab/s07/selinux/rustiron_capture.te lab/s07/selinux/rustiron_capture.if "$policy_build/"
cp packaging/selinux/rustiron_capture.fc packaging/selinux/rustiron_job_credential.* "$policy_build/"
cp packaging/selinux/rustiron_store_relay.te "$policy_build/"
cp packaging/selinux/rustiron_mail_relay.* "$policy_build/"
cp packaging/selinux/rustiron_app.* "$policy_build/"
set -- rustiron_executor rustiron_admin rustiron_coordinator rustiron_php rustiron_capture rustiron_job_credential rustiron_store_relay rustiron_mail_relay rustiron_app
for module do
    make -C "$policy_build" -f /usr/share/selinux/devel/Makefile "$module.pp"
    install -D -m 0644 "$policy_build/$module.pp" "$stage/usr/share/rustiron/selinux/$module.pp"
done

bin=$build/release
libexec=$stage/usr/libexec/rustiron
install -D -m 0755 "$bin/rustiron" "$stage/usr/bin/rustiron"
install -D -m 0755 "$bin/rustiron-control" "$libexec/rustiron-control"
install -D -m 0755 "$bin/rustiron-s02-executor" "$libexec/rustiron-executor"
install -D -m 0755 "$bin/rustiron-admin-helper" "$libexec/rustiron-admin-helper"
install -D -m 0755 "$bin/rustiron-restore-inventory" "$libexec/jobs/restore-inventory"
install -D -m 0755 "$bin/rustiron-capture-manifest" "$libexec/jobs/capture-manifest"
install -D -m 0755 "$bin/rustiron-migration-inventory" "$libexec/jobs/migration-inventory"

for unit in rustiron-admin-helper.service rustiron-coordinator.service rustiron-executor.service \
    rustiron-ols-boot-guard.service; do
    install -D -m 0644 "packaging/systemd/$unit" "$stage/usr/lib/systemd/system/$unit"
done
# Provisioning and the OLS capacity check read the PHP templates in /etc.
for unit in rustiron-site-php@.service rustiron-site-php@.socket \
    rustiron-site-sandbox-check@.service rustiron-site-sandbox-check@.timer \
    rustiron-app@.service rustiron-app-worker@.service; do
    install -D -m 0644 "packaging/systemd/$unit" "$stage/etc/systemd/system/$unit"
done
install -D -m 0755 lab/s03/check-site-sandbox.sh "$libexec/check-site-sandbox"
# W364: the package lshttpd unit has KillMode=none; W245 made mixed a product requirement.
install -D -m 0644 packaging/systemd/lshttpd.service.d/50-rustiron-killmode.conf \
    "$stage/etc/systemd/system/lshttpd.service.d/50-rustiron-killmode.conf"
# W381 (D-032): lshttpd wants the OLS boot guard and starts after it.
install -D -m 0644 packaging/systemd/lshttpd.service.d/51-rustiron-boot-guard.conf \
    "$stage/etc/systemd/system/lshttpd.service.d/51-rustiron-boot-guard.conf"
# W486 (W484-F3): a persistent system journal, so a power cut keeps its logs.
install -D -m 0644 packaging/journald/50-rustiron-persistent.conf \
    "$stage/etc/systemd/journald.conf.d/50-rustiron-persistent.conf"
# W569 (W558-F1): MariaDB answers on loopback only.
install -D -m 0644 packaging/mariadb/zz-rustiron-loopback.cnf \
    "$stage/etc/my.cnf.d/zz-rustiron-loopback.cnf"
# W386 (D-035): the scheduled capture and its missed-run check, and W466
# (D-061) WordPress jobs, and the D-083 alert check-in. Not enabled at
# installation; the operator enables them.
for unit in rustiron-scheduled-capture.service rustiron-scheduled-capture.timer \
    rustiron-scheduled-capture-check.service rustiron-scheduled-capture-check.timer \
    rustiron-site-cron.service rustiron-site-cron.timer \
    rustiron-alert-checkin.service rustiron-alert-checkin.timer; do
    install -D -m 0644 "packaging/systemd/$unit" "$stage/usr/lib/systemd/system/$unit"
done
# W317: store namespace and relay. Enabled only after store enrollment;
# W352: the relay units are templates named by the enrolled store port.
for unit in rustiron-store-netns.service rustiron-store-relay@.socket rustiron-store-relay@.service \
    rustiron-mail-relay@.socket rustiron-mail-relay@.service; do
    install -D -m 0644 "packaging/systemd/$unit" "$stage/usr/lib/systemd/system/$unit"
done
install -D -m 0644 packaging/mail/rustiron-mail-relay.php "$stage/usr/share/rustiron/rustiron-mail-relay.php"
install -D -m 0755 packaging/mail-relay.py "$libexec/mail-relay"
install -D -m 0755 packaging/store/rustiron-store-netns "$libexec/store-netns"
install -D -m 0755 packaging/alert/rustiron-alert-checkin "$libexec/alert-checkin"
install -D -m 0644 packaging/sysusers.d/rustiron-coordinator.conf "$stage/usr/lib/sysusers.d/rustiron-coordinator.conf"
# W348: the reviewed OLS parent that the installer writes once and pins.
install -D -m 0644 packaging/ols/httpd_config.conf "$stage/usr/share/rustiron/ols/httpd_config.conf"
# W487 (D-073): the PHP health file that each managed vhost serves.
install -D -m 0644 packaging/ols/php-health.php "$stage/usr/share/rustiron/ols/php-health.php"
install -D -m 0644 packaging/README.md "$stage/usr/share/doc/rustiron/README.md"
install -D -m 0644 LICENSE "$stage/usr/share/licenses/rustiron/LICENSE"

python3 scripts/release/release_manifest.py manifest "$stage"
python3 scripts/release/release_manifest.py check "$stage"
complete=yes
printf 'staging_root=%s\n' "$stage"
