"""
CertPilot Core - CLI Tool Module
명령줄 인터페이스 (CLI) 모듈
"""
import argparse
import sys
import logging
from datetime import datetime
from .server_manager import ServerManager
from .audit_storage import AuditLogWriter
from .certificate_manager import CertificateManager
from .ssh_integration import Server


def setup_logging(log_level: str = 'INFO'):
    """로깅 설정"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def create_parser() -> argparse.ArgumentParser:
    """명령줄 인자 파서 생성"""
    parser = argparse.ArgumentParser(
        description='CertPilot MVP - 인증서 점검 및 관리 도구',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  certpilot collect -s test-server.local -u admin -p ****** -o results.json
  certpilot verify -s test-server.local -u admin -p ****** -o report.txt
  certpilot audit -l /var/log/certpilot/audit.log
"""
    )
    
    # 서버 등록
    parser.add_argument(
        '-s', '--server', action='append', dest='servers',
        help='서버 호스트명 또는 IP (반복 가능)'
    )
    
    # 인증 정보
    parser.add_argument('-u', '--username', help='SSH 사용자명')
    parser.add_argument('-p', '--password', help='SSH 비밀번호 (보안을 위해 환경변수 사용 권장)')
    parser.add_argument('-P', '--port', type=int, default=22, help='SSH 포트 (기본: 22)')
    
    # 작업 모드
    parser.add_argument('-c', '--collect', action='store_true', help='인증서 수집')
    parser.add_argument('-v', '--verify', action='store_true', help='인증서 검증')
    parser.add_argument('-a', '--audit', action='store_true', help='감사 로그 관리')
    parser.add_argument('-l', '--log-file', default='/var/log/certpilot/audit.log', 
                        help='감사 로그 파일 경로')
    
    # 출력 옵션
    parser.add_argument('-o', '--output', help='출력 파일')
    parser.add_argument('-j', '--json', action='store_true', help='JSON 형식으로 출력')
    parser.add_argument('--quiet', '-q', action='store_true', help='조용한 모드')
    
    # 관리 옵션
    parser.add_argument('--add-server', action='store_true', help='서버 추가')
    parser.add_argument('--remove-server', action='store_true', help='서버 제거')
    parser.add_argument('--list-servers', action='store_true', help='서버 목록')
    
    return parser


def cmd_collect(args):
    """인증서 수집 작업"""
    logging.info(f"인증서 수집 시작: {args.servers}")
    
    manager = ServerManager()
    
    for hostname in args.servers:
        server = manager._create_server_from_dict({
            'hostname': hostname,
            'username': args.username,
            'port': args.port,
            'credentials': 'password' if args.password else 'key'
        })
        manager.add_server(server)
    
    results = manager.collect_certificates(
        servers=manager.get_servers(),
        ssh_user=args.username,
        ssh_password=args.password
    )
    
    # 결과 출력
    print(f"\n=== 수집 결과 ===")
    print(f"성공: {results['summary']['success']}")
    print(f"실패: {results['summary']['failed']}")
    
    for server in results['success']:
        print(f"\n[서버: {server['hostname']}]")
        for cert in server['certificates']:
            print(f"  - {cert['filename']}")
            print(f"    Subject: {cert['subject']}")
            print(f"    Valid: {cert['not_before']} ~ {cert['not_after']}")
    
    # JSON 출력
    if args.json:
        import json
        print("\n=== JSON 출력 ===")
        print(json.dumps(results, indent=2, default=str))


def cmd_verify(args):
    """인증서 검증 작업"""
    logging.info(f"인증서 검증 시작: {args.servers}")
    
    manager = CertificateManager()
    validator = ServerManager()
    
    for hostname in args.servers:
        server = validator._create_server_from_dict({
            'hostname': hostname,
            'username': args.username,
            'port': args.port,
            'credentials': 'password' if args.password else 'key'
        })
        manager.add_server(server)
    
    results = manager.verify_server_certificates(server)
    
    # 결과 출력
    print(f"\n=== 검증 결과 ===")
    print(f"서버: {results['server']['hostname']}")
    print(f"상태: {results['validation']['success']}")
    
    if results['validation']['error']:
        print(f"오류: {results['validation']['error']}")
    
    print(f"\n인증서: {results['validation']['total_count']}")
    print(f"유효: {results['validation']['valid_count']}")
    print(f"만료: {results['validation']['expired_count']}")
    print(f"아직 유효하지 않음: {results['validation']['not_yet_valid_count']}")
    
    # 상세 정보 출력
    for cert in results['validation']['certificates']:
        status = 'EXPIRED' if cert['is_expired'] else 'VALID'
        print(f"\n  [{cert['filename']}]")
        print(f"    Subject: {cert['subject']}")
        print(f"    Valid: {cert['not_before']} ~ {cert['not_after']} ({status})")


def cmd_audit(args):
    """감사 로그 관리 작업"""
    logging.info(f"감사 로그 관리: {args.log_file}")
    
    writer = AuditLogWriter(args.log_file, log_type="certpilot")
    
    # 테스트 이벤트 기록
    event = writer.write({
        'event_type': 'cert_collection',
        'description': '인증서 수집 시작',
        'details': {
            'server': args.servers[0] if args.servers else 'unknown',
            'timestamp': datetime.now().isoformat()
        }
    })
    
    print(f"감사 로그 기록 완료: {event['log_id']}")
    
    # 로그 읽기
    reader = AuditLogReader(args.log_file)
    logs = reader.read_all_logs()
    print(f"총 {len(logs)}개의 로그 항목")


def cmd_server(args):
    """서버 관리 작업"""
    manager = ServerManager()
    
    if args.add_server:
        server = Server(
            hostname=args.hostname,
            port=args.port,
            username=args.username,
            password=args.password
        )
        manager.add_server(server)
        print(f"서버 추가 완료: {server.hostname}")
    
    elif args.remove_server:
        manager.remove_server(args.hostname)
        print(f"서버 제거 완료: {args.hostname}")
    
    elif args.list_servers:
        servers = manager.get_servers()
        print(f"서버 목록: {len(servers)}개")
        for s in servers:
            print(f"  - {s['hostname']}:{s['port']} ({s['username']})")


def main():
    """메인 진입점"""
    parser = create_parser()
    args = parser.parse_args()
    
    # 로깅 설정
    setup_logging('INFO' if not args.quiet else 'WARNING')
    
    # 작업 실행
    if args.collect:
        cmd_collect(args)
    elif args.verify:
        cmd_verify(args)
    elif args.audit:
        cmd_audit(args)
    elif args.add_server or args.remove_server or args.list_servers:
        cmd_server(args)
    else:
        parser.print_help()
        print("\n예시:")
        print("  certpilot collect -s server1.local -s server2.local -u admin -p ******")
        print("  certpilot verify -s server1.local -u admin -p ******")
        print("  certpilot audit -l /var/log/certpilot/audit.log")


if __name__ == "__main__":
    main()
