"""설정 파일 JSON Schema(편집기 자동완성·사전 검증용). 최종 검증은 항상 `certdeploy validate` 가 한다."""
from .config import Options, WEBHOOK_FORMATS
from .handlers import CONTENT_KINDS, TYPES

_S, _I, _B = {"type": "string"}, {"type": "integer"}, {"type": "boolean"}
_PATH = {"type": "string", "pattern": "^/", "description": "절대 경로"}


def _options() -> dict:
    props = {}
    for k, v in vars(Options()).items():
        props[k] = {"type": "integer"} if isinstance(v, int) and not isinstance(v, bool) else {"type": type(v).__name__ if not isinstance(v, bool) else "boolean"}
    return {"type": "object", "additionalProperties": False, "properties": {k: {**v, "type": {"str": "string", "float": "number"}.get(v["type"], v["type"])} for k, v in props.items()}}


def _api() -> dict:
    step = {"type": "object", "required": ["name", "method", "url"], "properties": {
        "name": _S, "method": {"enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]}, "url": _S, "headers": {"type": "object"},
        "json": {}, "form": {"type": "object"}, "body": _S, "multipart": {"type": "object"}, "expect_status": {"type": "array", "items": _I},
        "expect_body": _S, "expect_json": {"type": "object"}, "extract": {"type": "object"}, "timeout": {"type": "number"}, "wait": {"type": "number"}}}
    steps = {"type": "array", "minItems": 1, "items": step}
    return {"type": "object", "required": ["steps"], "properties": {
        "base_url": {"type": "string", "pattern": "^https?://"}, "verify_tls": _B, "ca_file": _PATH, "timeout": {"type": "number"}, "vars": {"type": "object"},
        "pfx_password_env": _S, "pfx_alias": _S, "steps": steps, "rollback_steps": {"type": "array", "items": step}, "finally_steps": {"type": "array", "items": step}}}


def _target() -> dict:
    transport = {"type": "object", "properties": {"kind": {"enum": ["local", "ssh"]}, "host": _S, "user": _S, "port": _I, "key_file": _PATH,
                                                  "known_hosts": _PATH, "sudo": _B, "timeout": _I}}
    verify = {"type": "object", "required": ["host"], "additionalProperties": False,
              "properties": {"host": _S, "port": _I, "sni": _S, "strict": _B, "ca_file": _PATH, "lenient_x509": _B}}
    health = {"type": "object", "required": ["url"], "additionalProperties": False,
              "properties": {"url": {"type": "string", "pattern": "^https?://"}, "expect": _I, "timeout": {"type": "number"}, "insecure": _B}}
    files = {"type": "array", "items": {"type": "object", "required": ["path", "content"], "properties": {
        "path": _PATH, "content": {"enum": list(CONTENT_KINDS)}, "mode": _S, "password_env": _S, "password_file": _PATH, "alias": _S, "legacy_pkcs12": _B, "owner": _S}}}
    return {"type": "object", "required": ["name", "type"], "properties": {
        "name": {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"}, "type": {"enum": list(TYPES) + ["http_api", "manual", "iis"]}, "api": _api(),
        "iis": {"type": "object", "additionalProperties": False, "required": ["bindings"], "properties": {"store": _S, "powershell": {"enum": ["powershell", "pwsh"]}, "legacy_pkcs12": _B,
                "bindings": {"type": "array", "minItems": 1, "items": {"type": "object", "required": ["site"], "additionalProperties": False, "properties": {"site": _S, "port": _I, "host_header": _S, "ip": _S}}}}},
        "manual": {"type": "object", "properties": {"instructions": _S, "export_dir": _PATH, "formats": {"type": "array", "items": {"enum": ["pem", "pfx"]}},
                                                    "pfx_password_env": _S, "pfx_alias": _S, "remind_days": _I}},
        "owner": _S, "cert_content": {"enum": ["cert", "fullchain"]}, "key_format": {"enum": ["traditional", "pkcs8"]}, "transport": transport, "cert_path": _PATH, "key_path": _PATH, "keystore_path": _PATH, "format": {"enum": ["pkcs12", "jks", "pem"]},
        "password_env": _S, "password_file": _PATH, "alias": _S, "legacy_pkcs12": _B, "files": files,
        "check_cmd": _S, "reload_cmd": _S, "pre_cmd": _S, "post_cmd": _S, "verify": verify, "health": health,
        "order": _I, "canary": _B, "soak_seconds": _I, "soak_interval": _I, "hook_env": {"type": "array", "items": _S}}}


def _acme() -> dict:
    from .dnsprov import PROVIDER_REQUIRED
    dns_props = {"mode": {"enum": list(PROVIDER_REQUIRED)}, "check_resolvers": {"type": "array", "items": _S}, "propagation_timeout": _I}
    dns_props.update({m: {"type": "object", "required": list(req)} for m, req in PROVIDER_REQUIRED.items() if m != "manual"})
    dns = {"type": "object", "additionalProperties": False, "properties": dns_props}
    return {"type": "object", "required": ["domains"], "additionalProperties": False, "properties": {
        "directory": {"type": "string", "pattern": "^https://"}, "email": _S, "domains": {"type": "array", "minItems": 1, "items": _S},
        "key_type": {"enum": ["rsa2048", "rsa3072", "rsa4096", "ec256", "ec384"]}, "renew_days": _I, "dns": dns}}


def _approval() -> dict:
    return {"type": "object", "additionalProperties": False, "properties": {
        "required": _B, "approvers": {"type": "integer", "minimum": 1, "maximum": 3},
        "ttl_hours": {"type": "integer", "minimum": 1, "maximum": 720}, "self_approval": _B}}


def _backup() -> dict:
    target = {"type": "object", "required": ["kind", "path"], "properties": {"kind": {"enum": ["dir", "ssh"]}, "name": _S, "path": _PATH, "host": _S,
                                                                          "user": _S, "port": _I, "key_file": _PATH, "known_hosts": _PATH}}
    return {"type": "object", "additionalProperties": False, "properties": {
        "dir": _PATH, "passphrase_env": _S, "passphrase_file": _PATH, "keep_daily": _I, "keep_weekly": _I, "keep_monthly": _I, "verify": _B,
        "etc_dir": _PATH, "admin_data_dir": _PATH, "monitoring_dir": _PATH, "nginx_files": {"type": "array", "items": _PATH},
        "include": {"type": "array", "items": _PATH}, "exclude": {"type": "array", "items": _S}, "copy_to": {"type": "array", "items": target}}}


def config_schema() -> dict:
    target = _target()
    certset = {"type": "object", "properties": {"name": _S, "certificate": {"type": "object", "properties": {
        "cert_file": _PATH, "key_file": _PATH, "key_password_env": _S, "key_encryption": {"enum": ["none", "passphrase"]}}}, "lego": {"type": "object"}, "acme": _acme(), "approval": _approval(),
        "targets": {"type": "array", "items": target}}}
    notify = {"type": "object", "additionalProperties": False, "properties": {
        "alertmanager_url": {"type": "string", "pattern": "^https?://"}, "pushgateway_url": {"type": "string", "pattern": "^https?://"},
        "pushgateway_user": _S, "pushgateway_password_env": _S, "metrics_file": _PATH,
        "smtp": {"type": "object", "required": ["host", "from", "to"]},
        "webhook": {"type": "object", "properties": {"url_env": _S, "url_file": _PATH, "format": {"enum": list(WEBHOOK_FORMATS)}, "on_success": _B}}}}
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "certdeploy 설정", "type": "object",
            "properties": {"state_dir": _PATH, "audit_log": _PATH, "approval": _approval(), "backup": _backup(), "options": _options(), "notify": notify, "defaults": {"type": "object"},
                           "lego": {"type": "object", "properties": {"binary": _S, "email": _S, "dns_provider": _S, "domains": {"type": "array", "items": _S},
                                                                    "path": _PATH, "env_file": _PATH, "renew_days": _I, "server": _S, "dns_resolvers": {"type": "array", "items": _S}}},
                           "acme": _acme(), "certificate": certset["properties"]["certificate"], "targets": {"type": "array", "items": target},
                           "certificates": {"type": "array", "items": certset}}}
