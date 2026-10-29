"""관리자 화면(CertPilot 웹)용 설정 함수 — 웹 프레임워크와 무관한 순수 함수라 단독으로 시험할 수 있다.

화면에서 하는 일: ① 현황 보기 ② 메일 알림 설정·시험 메일 ③ 인증서별 개인키 보호(사용/사용 안 함) 전환.
설정은 `<state_dir>/settings.json`(0600)에 저장되어 certdeploy CLI·타이머가 자동으로 읽는다(YAML 보다 우선).
비밀번호·암호는 어떤 응답에도 포함하지 않는다(설정 여부만).
"""
import json
import os
from typing import Optional

import yaml

from . import approval, settings as st
from .bundle import BundleError, load_bundle
from .config import ConfigError, parse_config
from .manual import ManualError, convert_key_file, rekey_file
from .notify import MailTestError, send_test_mail
from .config import SmtpCfg


class AdminError(Exception):
    def __init__(self, message, status=422):
        super().__init__(message)
        self.status = status


def _yaml_cfg(config_path: Optional[str]):
    if not config_path:
        raise AdminError("서버에 CERTDEPLOY_CONFIG(certdeploy 설정 파일 경로)가 설정되어 있지 않습니다. 설치 매뉴얼의 관리자 화면 절을 참고하세요.", 409)
    try:
        with open(config_path, encoding="utf-8") as f:
            return parse_config(yaml.safe_load(f))          # 관리자 화면 값이 섞이지 않은 YAML 기준 설정
    except (OSError, yaml.YAMLError, ConfigError) as e:
        raise AdminError(f"certdeploy 설정 파일을 읽을 수 없습니다: {e}", 409)


def _settings(state_dir):
    try:
        return st.load(state_dir)
    except st.SettingsError as e:
        raise AdminError(str(e), 409)


def _last_run(state_dir: str) -> Optional[dict]:
    try:
        with open(os.path.join(state_dir, "last-run.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _key_state(path: str) -> Optional[bool]:
    try:
        return b"ENCRYPTED" in open(path, "rb").read(400)
    except OSError:
        return None


def overview(config_path: Optional[str]) -> dict:
    cfg = _yaml_cfg(config_path)
    data = _settings(cfg.state_dir)
    out = {"configured": True, "config_path": config_path, "state_dir": cfg.state_dir, "settings_updated_at": data.get("updated_at"),
           "settings_updated_by": data.get("updated_by"), "mail": None, "certificates": []}
    mail = data.get("mail")
    if mail is not None:
        m = st.mask({"mail": mail})["mail"]
        out["mail"] = {**m, "source": "관리자 화면"}
    elif cfg.notify.smtp:
        s = cfg.notify.smtp
        out["mail"] = {"enabled": True, "host": s.host, "port": s.port, "starttls": s.starttls, "from": s.sender, "to": s.to, "username": s.username,
                       "on_success": s.on_success, "password_set": bool(s.password_env or s.password_file), "source": "설정 파일(YAML)"}
    out["alertmanager_url"] = cfg.notify.alertmanager_url
    for cs in cfg.certs:
        o = (data.get("certificates") or {}).get(cs.name) or {}
        enc_cfg = o.get("key_encryption", cs.key_encryption)
        item = {"name": cs.name, "key_encryption": enc_cfg, "key_encryption_source": "관리자 화면" if "key_encryption" in o else "설정 파일(YAML)",
                "passphrase_set": bool(o.get("key_passphrase") or cs.key_password_env), "key_file": cs.key_file, "key_file_encrypted": _key_state(cs.key_file),
                "domains": (cs.acme or {}).get("domains") or [], "dns_mode": (cs.acme or {}).get("dns", {}).get("mode") if cs.acme else None,
                "targets": [{"name": t.name, "type": t.type} for t in cs.targets], "cert": None, "last_run": None}
        pw = o.get("key_passphrase")
        if not pw and cs.key_password_env:
            pw = os.environ.get(cs.key_password_env)
        try:
            b = load_bundle(cs.cert_file, cs.key_file, pw)
            item["cert"] = {"serial": f"{b.serial:x}", "not_after": b.not_after.isoformat(), "days_left": round(b.days_left(), 1), "names": b.names}
        except BundleError as e:
            item["cert_error"] = str(e)
        lr = _last_run(cs.state_dir)
        if lr:
            item["last_run"] = {"finished_at": lr.get("finished_at"), "ok": lr.get("ok"), "results": lr.get("results", [])}
        out["certificates"].append(item)
    return out


def save(config_path: Optional[str], payload: dict, actor: str) -> dict:
    """payload: {"mail": {...}} 및/또는 {"certificates": {이름: {"key_encryption": "none|passphrase", "key_passphrase": "..."}}}.
    개인키 보호를 바꾸면 이미 있는 키 파일도 즉시 변환한다(원본 사본은 검증 후 안전 삭제)."""
    cfg = _yaml_cfg(config_path)
    data = _settings(cfg.state_dir)
    changed = []
    new = json.loads(json.dumps(data))
    if "mail" in payload:
        try:
            new["mail"] = st.normalize_mail(payload["mail"] or {}, data.get("mail"))
        except st.SettingsError as e:
            raise AdminError("; ".join(e.problems))
        changed.append("mail")
    pending_conv = []
    if payload.get("certificates"):
        names = {c.name: c for c in cfg.certs}
        for name, opts in payload["certificates"].items():
            cs = names.get(name)
            if cs is None:
                raise AdminError(f"알 수 없는 인증서 이름: {name}")
            prev = (data.get("certificates") or {}).get(name) or {}
            prev_enc = prev.get("key_encryption", cs.key_encryption)
            try:
                norm = st.normalize_cert_opts(name, opts, prev)
            except st.SettingsError as e:
                raise AdminError("; ".join(e.problems))
            if prev_enc == "passphrase" and not prev.get("key_passphrase") and cs.key_password_env and os.environ.get(cs.key_password_env):
                prev = {**prev, "key_passphrase": os.environ[cs.key_password_env]}     # YAML/환경변수로 쓰던 암호를 이전 암호로 인정
            new.setdefault("certificates", {})[name] = norm
            pending_conv.append((cs, prev_enc, prev.get("key_passphrase"), norm))
            changed.append(f"certificates.{name}")
    messages = []
    for cs, prev_enc, prev_pp, norm in pending_conv:             # 설정을 저장하기 전에 파일을 변환(실패하면 아무것도 저장하지 않는다)
        state = _key_state(cs.key_file)
        try:
            if norm["key_encryption"] == "passphrase":
                if state is False:
                    convert_key_file(cs.key_file, norm["key_passphrase"], True, keep_backup=False)
                    messages.append(f"{cs.name}: 개인키 파일을 암호로 보호했습니다")
                elif state is True and prev_pp and prev_pp != norm["key_passphrase"]:
                    rekey_file(cs.key_file, prev_pp, norm["key_passphrase"])
                    messages.append(f"{cs.name}: 개인키 암호를 변경했습니다")
                elif state is True and not prev_pp:
                    raise AdminError(f"{cs.name}: 이미 암호로 보호된 키인데 이전 암호를 알 수 없습니다 — certdeploy key-decrypt 로 먼저 풀거나 기존 암호 환경변수를 설정하세요")
                else:
                    messages.append(f"{cs.name}: 개인키 보호 사용으로 저장했습니다" + ("" if state is not None else "(키 파일이 아직 없어 다음 발급·가져오기부터 암호로 저장됩니다)"))
            else:
                if state is True:
                    pp = prev_pp
                    if not pp:
                        raise AdminError(f"{cs.name}: 개인키 암호를 알 수 없어 평문으로 바꿀 수 없습니다(환경변수 또는 이전 암호 필요)")
                    convert_key_file(cs.key_file, pp, False, keep_backup=False)
                    messages.append(f"{cs.name}: 개인키 파일을 평문(권한 600)으로 바꿨습니다")
                else:
                    messages.append(f"{cs.name}: 개인키 보호 사용 안 함으로 저장했습니다")
        except ManualError as e:
            raise AdminError(f"{cs.name}: {e}")
    st.save(cfg.state_dir, new, actor)
    return {"changed": changed, "messages": messages, "settings": st.mask(new)}


def mail_test(config_path: Optional[str], payload: Optional[dict] = None, smtp_factory=None) -> dict:
    """저장된(또는 입력 중인) 메일 설정으로 시험 메일 1통. 성공/실패와 원인을 돌려준다(예외로 던지지 않는다)."""
    cfg = _yaml_cfg(config_path)
    data = _settings(cfg.state_dir)
    try:
        if payload:
            m = st.normalize_mail(payload, data.get("mail"))
            if not m["enabled"]:
                return {"ok": False, "message": "메일 알림이 '사용 안 함'으로 되어 있습니다"}
            scfg = SmtpCfg(m["host"], m["from"], m["to"], m["port"], m["starttls"], m["username"], None, None, m["on_success"], m["password"])
        else:
            mm = data.get("mail")
            if mm and mm.get("enabled", True):
                scfg = SmtpCfg(mm["host"], mm["from"], mm["to"], int(mm.get("port", 587)), bool(mm.get("starttls", True)), mm.get("username"), None, None, True, mm.get("password"))
            elif cfg.notify.smtp:
                scfg = cfg.notify.smtp
            else:
                return {"ok": False, "message": "저장된 메일 설정이 없습니다"}
    except st.SettingsError as e:
        return {"ok": False, "message": "; ".join(e.problems)}
    try:
        kw = {"smtp_factory": smtp_factory} if smtp_factory else {}
        send_test_mail(scfg, **kw)
    except MailTestError as e:
        return {"ok": False, "message": str(e)}
    return {"ok": True, "message": f"시험 메일을 보냈습니다: {', '.join(scfg.to)} (수신함을 확인하세요)"}


# ------------------------------------------------------------------ 배포 승인
def approvals(config_path: Optional[str]) -> dict:
    """인증서별 승인 정책과 대기·최근 요청(화면용)"""
    cfg = _yaml_cfg(config_path)
    out = []
    for cs in cfg.certs:
        try:
            reqs = approval.list_requests(cs.state_dir, include_closed=True)
        except approval.ApprovalError as e:
            raise AdminError(str(e), 500)
        reqs = [r for r in reqs if r.get("cert", cs.name) == cs.name][-10:]
        out.append({"cert": cs.name, "policy": cs.approval, "requests": list(reversed(reqs))})
    return {"certificates": out}


def decide(config_path: Optional[str], req_id: str, decision: str, actor: str, comment: str = "") -> dict:
    """화면에서 승인/반려. 승인자는 로그인한 관리자 계정(스스로 입력한 이름이 아님)"""
    if decision not in ("approve", "reject"):
        raise AdminError("decision 은 approve 또는 reject 여야 합니다")
    cfg = _yaml_cfg(config_path)
    cs = next((c for c in cfg.certs if any(r["id"] == req_id for r in approval.list_requests(c.state_dir, include_closed=True))), None)
    if not cs:
        raise AdminError("승인 요청을 찾을 수 없습니다", 404)
    try:
        r = approval.approve(cs.state_dir, req_id, actor, comment) if decision == "approve" else approval.reject(cs.state_dir, req_id, actor, comment)
    except approval.ApprovalError as e:
        raise AdminError(str(e))
    try:                                   # 지표·알림 정리는 실패해도 승인 결과에 영향이 없다
        from .notify import build_notifier
        from .runlog import push_metrics
        if cs.notify.pushgateway_url:
            pw = os.environ.get(cs.notify.pushgateway_password_env or "") if cs.notify.pushgateway_password_env else None
            push_metrics(cs.notify.pushgateway_url, cs.name, approval.metrics_text(cs.name, cs.state_dir), cs.notify.pushgateway_user, pw)
        if r["status"] in ("approved", "rejected"):
            build_notifier(cs.notify).resolve(f"approval:{cs.name}")
    except Exception:  # noqa: BLE001
        pass
    return {"cert": cs.name, "request": r}
