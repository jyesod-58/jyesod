# 수정본 검증 결과

검증 버전: 2.0.0. 실제 기관 시스템·실제 개인정보에 접근하지 않고 합성 응답으로 검증했습니다. Python 3.12, Node 24, 시스템 Chromium 154, Playwright를 사용했습니다. 기본 크롤러 의존성 전체 설치나 실제 외부 사이트 크롤링은 수행하지 않았습니다.

| 검사 | 결과 |
|---|---|
| 개인정보 규칙 회귀검사 | 32개 통과 |
| Burp 가져오기·브라우저 검사 | 24개 통과 |
| 크롤러·서버·변환 도구 Python 단위검사 | 42개 중 41개 통과, 1개 건너뜀 |
| UI 프로젝트 저장·복원·마스킹·다운로드 | 통과 |
| 실제 로컬 서버·iframe 연동·인증 검사 | 통과 |
| Python 및 HTML 내 JavaScript 구문검사 | 통과 |

Brotli 선택 패키지가 설치되어 있지 않아 Python 실코덱 검사 1개를 건너뛰었습니다. 패키지 누락 처리와 압축 오류·제한 처리 등은 별도로 검사했습니다. 브라우저의 Brotli 미지원 상태가 명시적으로 집계되는 것도 확인했습니다.

관리형 Chromium 정책이 file:// 이동을 차단해 HTML 파일을 직접 여는 E2E 단계도 별도로 건너뛰었습니다. HTML 스크립트·파일 선택·다운로드는 브라우저 내에서 검사했고, 실제 로컬 HTTP 서버를 통한 화면과 iframe에서의 합성 응답 가져오기도 통과했습니다. 사용 환경의 파일 열기 정책이 같으면 `python webapp.py --open` 또는 `run.bat`으로 실행하세요.

가져오기 검사는 gzip·deflate·chunked·EUC-KR, 손상 Base64의 항목별 격리, 같은 본문의 200/500 거래 보존, HTML 스크립트·일반/엔티티 속성·XML 속성·응답 헤더, WebSquare XML, 깊은 JSON 제한, PDF 미지원 집계, 실제 FileReader·파일 SHA-256, 정규화 원응답 해시 연결을 포함합니다. UI 검사는 원문 프로젝트 round-trip과 검토 판정 보존, 상세 마스킹, 마스킹 보고서에 합성 이메일·쿼리 토큰·오류 원문이 들어가지 않는지 확인했습니다. 이 시험은 모든 개인정보 형식이나 모든 XSS·기밀성 문제가 없음을 증명하지 않습니다.

재실행(테스트용 도구 설치 필요):

```bash
cd web-crawler
python -m unittest discover -s tests -p 'test_*.py' -v
node tests/test_detection.js
node tests/test_import_browser.js
node tests/test_ui.js
python tests/smoke_server_browser.py
```

브라우저 테스트는 Node의 `playwright` 및 Python의 `playwright`가 필요합니다. JavaScript 테스트는 `CHROMIUM_PATH` 환경변수로 브라우저 경로를 바꿀 수 있으며 기본 경로는 `/usr/bin/chromium`입니다. 테스트는 일반 사용을 위한 필수 설치 항목이 아닙니다. 일부 테스트는 소스 함수를 추출하거나 브라우저 메모리 안에서만 테스트용 접근자를 추가합니다.

실제 Burp 버전과 내보내기 설정, 사이트별 권한·업무 응답, 기관별 필드와 번호 형식의 재현율, 대용량 운영 성능은 배포 환경에서 추가 검증해야 합니다. ‘완료’ 건수는 규칙 실행의 회계이며 개인정보 부재 판정이 아닙니다.
