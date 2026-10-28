# 인증서 발급·갱신 자동화 설계 (Let's Encrypt + lego + Infoblox DNS-01)

> **상태: certdeploy 로 구현됨**(자동 테스트 통과). 단 실제 lego·Infoblox·각 서비스 서버에서의 시험은 하지 못했다 — [검증 현황](certdeploy.md). 스테이징 CA 로 먼저 검증한 뒤 운영에 적용한다.
> 감시는 [monitoring/](../../monitoring/README.md) 가 맡고, 이 문서는 발급·배포 쪽 설계다.

## 1. 왜 이 구성인가
- 와일드카드 인증서는 **DNS-01 인증만 가능**하다. 서버가 외부에서 접근되지 않아도 되고, 도메인의 DNS 가 공개적으로 응답하기만 하면 된다.
- 교내 DNS 가 Infoblox 이므로 API(WAPI)로 TXT 레코드를 자동 등록할 수 있다.
- 서버가 50대 이하이고 WebtoB/JEUS·IIS 가 섞여 있어 서버마다 ACME 클라이언트를 두기보다 **발급 서버 1대에서 발급하고 배포**하는 편이 관리 지점이 적다.
- 공인 인증서 최대 유효기간이 계속 짧아진다(CA/브라우저 포럼 일정: 2026-03 200일 → 2027-03 100일 → 2029 47일 — **일정은 제가 아는 범위이므로 확인 필요**). 수동 교체는 곧 한계가 온다.

## 2. 구조
```
[발급 서버(Linux, 전용 계정)] ── DNS-01 ──▶ Infoblox(위임 하위 영역) ◀── Let's Encrypt 검증
   certdeploy renew (lego 호출, systemd 타이머)
        │ certdeploy: 검증 → 서버별 백업·교체 → 점검 → 재로드 → TLS 일련번호 확인 → 실패 시 롤백·알림
        ▼
   Apache · Tomcat · WebtoB/JEUS · IIS · Node.js        ◀─ monitoring 스택이 결과를 독립 검증
```

## 3. Infoblox 설계 (권한 최소화)
**하위 영역 위임 방식(권장)**: 메인 영역에는 영구 CNAME 한 줄만 두고, 인증용 TXT 는 별도 하위 영역에서만 쓴다.
1. Infoblox 에 전용 영역 생성: 예) `acme.univ.example`
2. 메인 영역에 CNAME 등록: `_acme-challenge.univ.example  CNAME  _acme-challenge.acme.univ.example`
   (와일드카드 `*.univ.example` 과 `univ.example` 는 모두 `_acme-challenge.univ.example` 하나로 검증됨)
3. API 전용 계정을 만들고 **그 하위 영역에만** TXT 레코드 쓰기 권한 부여(관리자 그룹·영역 권한 기능). 메인 영역 권한은 주지 않는다.
4. 발급 서버에서 WAPI(HTTPS) 접근 허용(방화벽), 계정 비밀번호는 `/etc/lego/lego.env`(권한 600)에만 보관
5. 전파 확인: 발급 서버에서 `dig TXT _acme-challenge.univ.example` 가 위임을 따라 응답하는지, **외부(공개) DNS 에서도 조회되는지** 확인

확인할 것: 이 도메인의 권한 DNS 가 Infoblox 인지, 상위 기관이 위임한 구조인지, Infoblox 버전과 WAPI 사용 허용 정책.

## 4. 구현: certdeploy
발급(lego 호출)과 배포를 하나로 묶은 도구 **[certdeploy](certdeploy.md)** 로 구현했다(`certdeploy/` 패키지, 자동 테스트 포함).
- lego 환경변수·스테이징 시험·타이머 설정은 certdeploy 설정(`lego:` 항목)과 [certdeploy 가이드](certdeploy.md) 4절 절차를 따른다.
- **Infoblox 환경변수 이름은 버전마다 다를 수 있으므로 설치한 lego 로 확인:** `lego dnshelp -c infoblox`
- 반드시 **스테이징 먼저**(`certdeploy issue --staging --no-deploy`), 그다음 canary 한 대 → 전체 순서

## 5. 배포와 서비스별 주의
배포 엔진은 점검 → 재로드 → **TLS 로 새 인증서 확인** → 실패 시 자동 롤백 순서로 한 대씩 진행한다.
- Apache/nginx/Node.js(PEM), Tomcat(PKCS#12·JKS·PEM)은 내장 유형, **WebtoB·JEUS 는 `generic` 유형으로 파일 목록과 명령을 직접 지정** — 제품 버전별 인증서 형식·재기동 방식은 벤더 문서로 확인해 설정에 채운다
- IIS 는 자동 배포 대상이 아니다(`certdeploy/deploy-iis.ps1` 초안)
- 오래된 클라이언트(구형 Java, Android 7.1 이하 등)가 접속하는 서비스는 Let's Encrypt 루트 신뢰 여부를 사전 점검

## 6. 개인키 취급 원칙
- 와일드카드 키를 많은 서버에 복사하면 한 곳의 침해가 전체로 번진다. **와일드카드는 필요한 서비스에만**, 나머지는 호스트별 인증서(SAN)로 분리 검토
- 개인키 파일 권한 600, 전달은 SSH 로만, 로그·메신저·티켓에 붙여넣지 않는다
- 발급 서버는 다른 용도로 쓰지 않고 접근 계정을 최소화

## 7. 전환 계획 (교체 체크리스트 연동)
[교체 체크리스트](cert-rotation-checklist.md)의 일정대로 진행한다. 11월 5일까지 스테이징·1~2대 실배포 검증이 끝나지 않으면 방식 A(수동 갱신)로 확정하고, 자동화는 이후 일정에서 완성한다.

## 8. 완료 기준
- [ ] 스테이징 발급 성공(`certdeploy issue --staging --no-deploy`)
- [ ] Apache canary 에서 배포 → 재로드 → 일련번호 확인까지 자동 수행, 의도적 실패 시 롤백 확인
- [ ] 각 서비스(Tomcat, WebtoB/JEUS, Node.js)의 `reload_cmd`·파일 형식을 제품 문서로 확인해 설정·시험
- [ ] 갱신 실패 시 알림(타이머 실패 + 감시 스택의 갱신 지연 경보)이 담당자에게 도착
- [ ] 개인키·계정 정보 보관 위치와 권한 점검, 복구 절차 문서화
