#!/usr/bin/env bash
# 설치 스크립트 실제 실행 시험 장치: 마운트 네임스페이스에서 /etc /opt /var/lib /var/backups /var/log /root 를 overlay 로 덮고
# (변경은 임시 폴더에만 남고 끝나면 사라짐) dnf·systemctl·docker 등 시스템 명령만 가짜로 바꿔 install-mgmt-server.sh 를 비-dry-run 으로 돌린다.
# 사용: installer_harness.sh <시나리오> <작업폴더> [설치 스크립트 옵션...]   시나리오: full | rerun | resume | minimal | notrocky
set -Eeuo pipefail
SCEN="$1"; WORK="$2"; shift 2
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 가짜 명령 폴더는 다른 계정(certdeploy)도 실행·기록할 수 있게 누구나 접근 가능한 위치에 둔다(작업 폴더는 pytest 가 700 으로 만든다)
STUBDIR="$(mktemp -d /tmp/ci-stubs.XXXXXX)"; chmod 755 "$STUBDIR"; trap 'rm -rf "$STUBDIR"' EXIT
mkdir -p "$WORK/up" "$WORK/wk" "$STUBDIR/bin"
export STUBLOG="$STUBDIR/stub.log"; : >"$STUBLOG"; chmod 666 "$STUBLOG"

stub() { # 이름 본문
  printf '#!/usr/bin/env bash\necho "$(basename "$0") $*" >>"$STUBLOG"\n%s\n' "$2" >"$STUBDIR/bin/$1"; chmod +x "$STUBDIR/bin/$1"
}
stub dnf 'case " $* " in *" nginx "*) mkdir -p /etc/nginx/conf.d;; esac; exit 0'
for c in hostnamectl timedatectl firewall-cmd setsebool vmware-toolbox-cmd restorecon nginx; do stub "$c" 'exit 0'; done
stub ssh-keygen 'f=""; while [ $# -gt 0 ]; do [ "$1" = -f ] && f="$2"; shift; done; mkdir -p "$(dirname "$f")"; echo PRIVATE >"$f"; chmod 600 "$f"; echo "ssh-ed25519 AAAATESTKEY certdeploy@test" >"$f.pub"'
stub systemctl 'case "$1" in is-active) echo active; exit 0;; esac; exit 0'
stub systemd-detect-virt 'echo vmware'
stub getenforce 'echo Enforcing'
stub curl 'exit 0'
stub docker 'if [ "${STUB_DOCKER_FAIL:-0}" = 1 ] && [ "$1 $2" = "run --rm" ] && [ "${3:-}" = hello-world ]; then echo "docker 시험 실패" >&2; exit 1; fi
if [ "$1" = compose ] && [ "$2" = ps ]; then printf "a\nb\nc\nd\ne\n"; fi; exit 0'
stub git 'if [ "$1" = clone ]; then mkdir -p "$3"; tar -C "'"$REPO"'" --exclude=.git -cf - . | tar -C "$3" -xf -; fi; exit 0'
cat >"$STUBDIR/bin/python3" <<PY
#!/usr/bin/env bash
if [ "\${1:-}" = "-m" ] && [ "\${2:-}" = "venv" ]; then echo "python3 \$*" >>"$STUBLOG"; exec /usr/bin/python3 -m venv --system-site-packages "\$3"; fi
exec /usr/bin/python3 "\$@"
PY
chmod +x "$STUBDIR/bin/python3"

INNER="$WORK/inner.sh"
cat >"$INNER" <<'IN'
set -Eeuo pipefail
for d in /etc /opt /var/lib /var/backups /var/log /root; do
  n="$(echo "$d" | tr / _)"; mkdir -p "$WORK/up/$n" "$WORK/wk/$n"
  mount -t overlay overlay -o "lowerdir=$d,upperdir=$WORK/up/$n,workdir=$WORK/wk/$n" "$d"
done
export PATH="$STUBDIR/bin:$PATH" PIP_NO_INDEX=1 PIP_NO_BUILD_ISOLATION=0 PIP_DISABLE_PIP_VERSION_CHECK=1
if [ "$SCEN" = notrocky ]; then printf 'ID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME="Ubuntu 24.04"\n' >/etc/os-release
else printf 'ID=rocky\nVERSION_ID="10.0"\nPRETTY_NAME="Rocky Linux 10.0 (Test)"\n' >/etc/os-release; fi
run_install() { bash "$REPO/scripts/install-mgmt-server.sh" --yes --no-network-check --skip-update --local-src "$REPO" "$@"; }
set +e
case "$SCEN" in
  full|minimal|notrocky) run_install "$@" >"$WORK/install1.out" 2>&1; echo $? >"$WORK/rc1" ;;
  rerun) run_install "$@" >"$WORK/install1.out" 2>&1; echo $? >"$WORK/rc1"; run_install "$@" >"$WORK/install2.out" 2>&1; echo $? >"$WORK/rc2" ;;
  resume) STUB_DOCKER_FAIL=1 run_install "$@" >"$WORK/install1.out" 2>&1; echo $? >"$WORK/rc1"
          ls /var/lib/cert-install >"$WORK/done_after_fail" 2>/dev/null
          run_install "$@" >"$WORK/install2.out" 2>&1; echo $? >"$WORK/rc2" ;;
esac
set -e
cp "$STUBLOG" "$WORK/stub.log"
if [ -n "${VERIFY:-}" ]; then /usr/bin/python3 "$VERIFY" "$SCEN" "$WORK"; fi
IN
export WORK REPO SCEN STUBLOG STUBDIR
unshare -m --propagation private bash "$INNER" "$@"
