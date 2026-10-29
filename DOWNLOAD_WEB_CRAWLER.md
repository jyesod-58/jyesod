# 개인정보 응답 검토기 2.0.0 다운로드

[수정본 ZIP 다운로드](downloads/web-crawler-v2.0.0.zip?raw=true)

위 링크로 ZIP을 받은 뒤 압축을 풀고 `web-crawler/pii_finder.html`을 최신 Chrome/Edge에서 여세요. Burp HTTP history에서 응답을 포함해 **Save selected items**로 내보낸 XML을 불러올 수 있습니다. 파일 열기가 기관 브라우저 정책으로 차단되면 `python webapp.py --open` 또는 `run.bat`으로 로컬 서버를 실행하세요.

[사용법](web-crawler/README.md) · [검증 결과와 제한](web-crawler/VALIDATION.md) · [변경 내역](web-crawler/CHANGES.md)

프로젝트 저장 파일은 원문을 포함한 평문 민감자료입니다. 분석 실패·미지원·일부 검사 건수를 확인하고, 자동 탐지를 개인정보 부재나 취약점 안전 판정으로 사용하지 마세요. PDF/OCR은 별도 검토가 필요하며, Brotli 변환 도구는 ZIP에 포함되어 있습니다.

ZIP SHA-256: `0c3366ff7d215ec46a6d26be0b78c0adb3184c696b4813c7b086ed0d152bf179`

합성 응답 기반 검증을 수행했으며 실제 기관 대상 외부 크롤링은 검증하지 않았습니다. 기존 master의 README는 변경하지 않았습니다.
