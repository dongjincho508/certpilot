"""
CertPilot Core - Certificate Parser Module
PEM/PKCS#12/JKS 인증서 파싱 모듈
"""
import subprocess
import tempfile
import os
from datetime import datetime
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class CertificateInfo:
    """인증서 정보 데이터 클래스"""
    subject: str
    issuer: str
    serial: str
    not_before: datetime
    not_after: datetime
    version: int
    signature_algorithm: str
    public_key_algorithm: str
    public_key_bits: int
    is_expired: bool
    is_not_yet_valid: bool
    subject_alt_name: List[str] = None

    def __post_init__(self):
        if self.subject_alt_name is None:
            self.subject_alt_name = []


def parse_pem_certificates(cert_path: str) -> List[CertificateInfo]:
    """
    PEM 형식 인증서 파싱
    단일 또는 멀티파트 PEM 인증서를 파싱하여 인증서 정보를 반환
    """
    certs = []
    current_cert = []
    
    with open(cert_path, 'r') as f:
        for line in f:
            if line.strip().startswith('-----BEGIN CERTIFICATE-----'):
                current_cert = [line]
            elif line.strip().startswith('-----END CERTIFICATE-----'):
                current_cert.append(line)
                cert_pem = ''.join(current_cert)
                cert_info = _parse_pem_cert(cert_pem)
                if cert_info:
                    certs.append(cert_info)
                current_cert = []
            elif current_cert:
                current_cert.append(line)
    
    return certs


def _parse_pem_cert(cert_pem: str) -> Optional[CertificateInfo]:
    """PEM 인증서 하나를 파싱"""
    try:
        # OpenSSL 명령 실행
        result = subprocess.run(
            ['openssl', 'x509', '-noout', '-text'],
            input=cert_pem,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            return None
        
        output = result.stdout
        cert_info = _parse_x509_output(output)
        return cert_info
        
    except Exception as e:
        return None


def _parse_x509_output(output: str) -> Optional[CertificateInfo]:
    """OpenSSL x509 -noout -text 출력 파싱"""
    import re
    
    cert_info = CertificateInfo(
        subject="",
        issuer="",
        serial="",
        not_before=datetime.now(),
        not_after=datetime.now(),
        version=0,
        signature_algorithm="",
        public_key_algorithm="",
        public_key_bits=0,
        is_expired=False,
        is_not_yet_valid=False
    )
    
    # Subject 파싱
    subject_match = re.search(r'Subject:\s+(.*)', output)
    if subject_match:
        cert_info.subject = subject_match.group(1).strip()
    
    # Issuer 파싱
    issuer_match = re.search(r'Issuer:\s+(.*)', output)
    if issuer_match:
        cert_info.issuer = issuer_match.group(1).strip()
    
    # Serial 파싱
    serial_match = re.search(r'Serial Number:\s+(.*)', output)
    if serial_match:
        cert_info.serial = serial_match.group(1).strip()
    
    # Validity dates 파싱
    not_before_match = re.search(r'Not Before:\s+(.*)', output)
    not_after_match = re.search(r'Not After:\s+(.*)', output)
    
    if not_before_match:
        try:
            cert_info.not_before = datetime.strptime(
                not_before_match.group(1).strip(),
                '%b %d %H:%M:%S %Y %Z'
            )
        except ValueError:
            # 시간대 제거
            try:
                cert_info.not_before = datetime.strptime(
                    not_before_match.group(1).strip(),
                    '%b %d %H:%M:%S %Y'
                )
            except ValueError:
                pass
    
    if not_after_match:
        try:
            cert_info.not_after = datetime.strptime(
                not_after_match.group(1).strip(),
                '%b %d %H:%M:%S %Y %Z'
            )
        except ValueError:
            try:
                cert_info.not_after = datetime.strptime(
                    not_after_match.group(1).strip(),
                    '%b %d %H:%M:%S %Y'
                )
            except ValueError:
                pass
    
    # Version 파싱
    version_match = re.search(r'Version:\s+(\d+)', output)
    if version_match:
        cert_info.version = int(version_match.group(1))
    
    # Signature Algorithm 파싱
    sig_alg_match = re.search(r'Signature Algorithm:\s+(.*)', output)
    if sig_alg_match:
        cert_info.signature_algorithm = sig_alg_match.group(1).strip()
    
    # Public Key Algorithm 파싱
    pub_key_match = re.search(r'Public Key Algorithm:\s+(.*)', output)
    if pub_key_match:
        cert_info.public_key_algorithm = pub_key_match.group(1).strip()
    
    # Public Key Bits 파싱
    key_bits_match = re.search(r'Public-Key:\s+(\d+ bit)', output)
    if key_bits_match:
        cert_info.public_key_bits = int(key_bits_match.group(1))
    
    # Subject Alternative Name 파싱
    san_match = re.search(r'Subject Alternative Name:\s+(.*)', output)
    if san_match:
        cert_info.subject_alt_name = [san_match.group(1).strip()]
    
    # 인증서 유효성 검사
    now = datetime.now()
    cert_info.is_expired = cert_info.not_after < now
    cert_info.is_not_yet_valid = cert_info.not_before > now
    
    return cert_info


def parse_pkcs12(pfx_path: str, pfx_password: str = None) -> List[CertificateInfo]:
    """
    PKCS#12 (.pfx/.p12) 인증서 파싱
    """
    certs = []
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            # OpenSSL로 PKCS#12를 PEM으로 변환
            cmd = ['openssl', 'pkcs12', '-in', pfx_path, '-out', tmp_path, '-nodes']
            if pfx_password:
                cmd.extend(['-passin', f'pass:{pfx_password}'])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # 변환된 PEM 파일 파싱
                certs = parse_pem_certificates(tmp_path)
            else:
                # 오류 로깅
                print(f"PKCS#12 파싱 오류: {result.stderr}")
                
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    except Exception as e:
        print(f"PKCS#12 파싱 에러: {e}")
    
    return certs


def parse_jks(jks_path: str, keytool_path: str = 'keytool') -> List[CertificateInfo]:
    """
    JKS (Java KeyStore) 인증서 파싱
    (Java keytool이 필요하고, JKS 파일을 PEM으로 변환)
    """
    certs = []
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            # JKS를 PFX로 변환 (keytool 사용)
            cmd = [
                keytool_path, '-importkeystore',
                '-srckeystore', jks_path,
                '-srcstoretype', 'JKS',
                '-destkeystore', tmp_path + '.pfx',
                '-deststoretype', 'PKCS12'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # PFX를 PEM으로 변환
                openssl_cmd = [
                    'openssl', 'pkcs12', '-in', tmp_path + '.pfx',
                    '-out', tmp_path, '-nodes'
                ]
                result2 = subprocess.run(openssl_cmd, capture_output=True, text=True, timeout=60)
                
                if result2.returncode == 0:
                    certs = parse_pem_certificates(tmp_path)
            
            os.unlink(tmp_path + '.pfx')
            
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    except Exception as e:
        print(f"JKS 파싱 에러: {e}")
    
    return certs


if __name__ == "__main__":
    # 테스트
    import sys
    if len(sys.argv) > 1:
        cert_path = sys.argv[1]
        if cert_path.endswith('.pem'):
            certs = parse_pem_certificates(cert_path)
        elif cert_path.endswith(('.pfx', '.p12')):
            certs = parse_pkcs12(cert_path, pfx_password='changeit')
        else:
            certs = parse_pem_certificates(cert_path)
        
        for i, cert in enumerate(certs):
            print(f"=== 인증서 {i+1} ===")
            print(f"Subject: {cert.subject}")
            print(f"Issuer: {cert.issuer}")
            print(f"Serial: {cert.serial}")
            print(f"Not Before: {cert.not_before}")
            print(f"Not After: {cert.not_after}")
            print(f"Version: {cert.version}")
            print(f"Signature Algorithm: {cert.signature_algorithm}")
            print(f"Public Key: {cert.public_key_algorithm} ({cert.public_key_bits} bit)")
            print(f"Expired: {cert.is_expired}")
            print(f"Not Yet Valid: {cert.is_not_yet_valid}")
            print()