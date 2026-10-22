"""
CertPilot Core - 인증서 점검 및 검증 핵심 모듈
SSH 기반 원격 서버 인증서 수집/검증/감사 로그 관리

주요 기능:
- PEM/PKCS#12/JKS 인증서 파싱
- SSH 기반 원격 서버 접속 및 인증서 수집
- WORM(Write Once Read Many) 감사 로그 저장
- 서버 인증서 검증 및 변경 감지

사용 예:
    from certpilot_core.cert_parser import parse_pem_certificates
    from certpilot_core.ssh_integration import Server, SSHClientWrapper

설치:
    pip install paramiko
"""

__version__ = "0.1.0"
__author__ = "CertPilot Team"
__description__ = "Enterprise SSL/TLS certificate automation platform"
