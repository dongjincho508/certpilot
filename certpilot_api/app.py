"""
CertPilot API - REST API 모듈
관리 인터페이스용 REST API
"""
from flask import Flask, request, jsonify
from datetime import datetime
from typing import List, Dict, Any
from .server_manager import ServerManager
from .certificate_manager import CertificateManager
from .audit_storage import AuditLogWriter

app = Flask(__name__)

# 전역 매니저 인스턴스
server_manager = ServerManager()
certificate_manager = CertificateManager()
audit_writer = AuditLogWriter('/var/log/certpilot/audit', log_type='certpilot')


@app.route('/servers', methods=['GET', 'POST'])
def manage_servers():
    """
    서버 관리
    GET: 서버 목록
    POST: 서버 등록
    """
    if request.method == 'GET':
        servers = server_manager.get_servers()
        return jsonify({
            'status': 'success',
            'servers': servers
        })
    
    else:  # POST
        data = request.json
        required_fields = ['hostname', 'username']
        
        if not all(k in data for k in required_fields):
            return jsonify({'error': 'hostname과 username은 필수입니다.'}), 400
        
        server = server_manager._create_server_from_dict(data)
        server_manager.add_server(server)
        
        return jsonify({
            'status': 'success',
            'message': f'서버 {server.hostname} 등록 완료',
            'server': server.to_dict()
        }), 201


@app.route('/servers/<hostname>', methods=['DELETE'])
def delete_server(hostname):
    """서버 삭제"""
    try:
        server_manager.remove_server(hostname)
        return jsonify({'status': 'success', 'message': f'서버 {hostname} 삭제 완료'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/servers/<hostname>/certificates', methods=['GET'])
def get_server_certificates(hostname):
    """
    특정 서버의 인증서 조회
    """
    server = server_manager._create_server_from_dict({
        'hostname': hostname,
        'username': request.args.get('username'),
        'port': request.args.get('port', 22),
        'credentials': 'password'
    })
    
    result = certificate_manager.verify_server_certificates(server)
    
    return jsonify({
        'status': 'success',
        'certificates': result['validation']['certificates']
    })


@app.route('/servers/<hostname>/certificates/<cert_id>/verify', methods=['POST'])
def verify_certificate(hostname, cert_id):
    """
    특정 인증서 검증
    """
    data = request.json
    if not data:
        return jsonify({'error': '요청 본문 필요'}), 400
    
    # 검증 수행
    cert_info = certificate_manager._parse_single_cert(
        None,  # SSH 클라이언트 다운스트림에서 처리
        data.get('cert_content', '')
    )
    
    if not cert_info:
        return jsonify({'error': '인증서 파싱 실패'}), 400
    
    return jsonify({
        'status': 'success',
        'certificate': {
            'subject': cert_info['subject'],
            'issuer': cert_info['issuer'],
            'serial': cert_info['serial'],
            'not_before': cert_info['not_before'],
            'not_after': cert_info['not_after'],
            'is_expired': cert_info['is_expired'],
            'is_not_yet_valid': cert_info['is_not_yet_valid']
        }
    })


@app.route('/audit-logs', methods=['GET'])
def get_audit_logs():
    """
    감사 로그 조회
    """
    limit = request.args.get('limit', 100, type=int)
    
    # 감사 로그는 파일 기반이므로 실제 구현에서는 별도 처리
    return jsonify({
        'status': 'success',
        'logs': [],
        'message': '감사 로그 경로는 /var/log/certpilot/audit에 저장됩니다.'
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
