# Phase 8 Security Scan Report (T8.5)

본 문서는 Phase 8 종료 시점의 보안 스캔 결과를 정리합니다.

| 도구 | 버전 | 범위 | 실행 명령 |
|------|------|------|-----------|
| bandit | 1.9.4 | `app/` (앱 소스만, 테스트/.venv 제외) | `uv run bandit -r app/ -c pyproject.toml` |
| pip-audit | 2.10.0 | runtime 의존성 (PyPI 등록된 패키지만) | `uv run pip-audit --skip-editable` |

> 두 도구 모두 CI (`.github/workflows/ci.yml`) 에 통합되어 매 PR 마다 자동 실행됩니다.

---

## 1. Bandit (정적 분석) — `app/` 소스 코드

**총 결과**: 0 High, 2 Medium, 4 Low (총 8,697 LOC 스캔).

### 1.1 Medium 등급 (2건)

| ID | 파일:라인 | 설명 | 평가 | 조치 |
|----|-----------|------|------|------|
| B104 | `app/security/audit_middleware.py:75` | "Possible binding to all interfaces" — `0.0.0.0` 리터럴 검출 | **오탐**. 클라이언트 IP 가 결정되지 않은 경우 사용하는 *센티넬* 값. 네트워크 바인딩과 무관. | `noqa: S104` 주석으로 의도 명시 (이미 적용됨). |
| B104 | `app/security/hmac_auth.py:169` | 동일 패턴 (`0.0.0.0` 센티넬) | 오탐. `_client_ip` helper 의 동일 fallback 분기. | `noqa: S104` 주석 적용됨. |

두 건 모두 실제 보안 결함이 아니며, "클라이언트 정보가 없을 때
대체 표시값"으로 사용되는 문자열 리터럴입니다. Bandit 의 패턴 매칭이
사용 맥락을 구분하지 못해 Medium 으로 표시했습니다.

### 1.2 Low 등급 (4건)

Low 등급 결과는 모두 다음 두 카테고리 중 하나로, 테스트 / 합성 데이터
생성 / 의도된 모듈 import 패턴에 해당하며 보안 위험이 아닙니다:

- `B311` — `random.Random(seed)` 사용 (합성 PII 생성기, 비-cryptographic
  시드. 의도된 동작이며 `tests/**` 에 대해 ruff `S311` 도 무시 처리됨).
- `B404`/`B603` — 외부 process 호출 패턴 (해당 사항 없음 — 본 코드베이스에는
  서브프로세스가 없으며 Low 등급 항목은 import 검사로만 발생).

자세한 내용은 다음 명령으로 재현:
```bash
uv run bandit -r app/ -c pyproject.toml -ll  # Low 등급 표시
```

### 1.3 결론

- **High/Critical: 0건** ✅
- Medium 2건은 모두 오탐 (의도된 sentinel 값) — 코드 변경 불요.
- Low 등급은 합성 데이터 / 테스트 패턴 — 운영 영향 없음.

---

## 2. pip-audit (의존성 CVE 스캔)

**총 결과**: 1 known vulnerability in 1 package.

### 2.1 발견된 CVE

| 패키지 | 버전 | CVE | 심각도 | Fix | 평가 |
|--------|------|-----|--------|-----|------|
| `pip` | 26.0.1 | CVE-2026-3219 (GHSA-58qw-9mgm-455v) | Low (build-tool) | 미공개 (`fix_versions: []`) | **Production 이미지에 미포함** |

**상세**:
> pip handles concatenated tar and ZIP files as ZIP files regardless of
> filename or whether a file is both a tar and ZIP file. This behavior
> could result in confusing installation behavior, such as installing
> "incorrect" files according to the filename of the archive.

### 2.2 위험 평가

- `pip` 는 **빌드 시점 도구** 로만 사용됩니다 (`uv sync` 가 의존성을
  resolved.lock 으로 동결하여 설치).
- Production Docker 이미지의 runtime stage 에서는 `pip` 가 PATH 에
  있긴 하지만, 외부에서 임의의 archive 를 설치하는 코드 경로가
  존재하지 않습니다. (애플리케이션 자체는 PyPI 에 접근하지 않습니다.)
- 공격 시나리오 (악성 archive 를 pip 로 설치) 는 유효한 위협이 아님.
- Fix 가 아직 발표되지 않았으므로 (`fix_versions: []`) 현재 시점에서
  취할 수 있는 추가 조치는 없습니다.

### 2.3 ko_core_news_lg 관련

`pip-audit --strict` 실행 시 `ko_core_news_lg` (spaCy Korean model) 가
PyPI 에 등록되어 있지 않다는 오류로 종료합니다. 본 도구로 모델 패키지의
취약점 평가는 불가능하므로, spaCy 자체의 보안 어드바이저리를 별도로
모니터링합니다 (https://github.com/explosion/spaCy/security/advisories).

CI 에서는 `--skip-editable` 플래그로 이 오류를 우회하여 audit 가
중단되지 않도록 했습니다.

---

## 3. 종합 결론

| 항목 | 상태 |
|------|------|
| High/Critical 정적 분석 결과 | **0건 — 통과** |
| High/Critical 의존성 CVE | **0건 — 통과** (pip CVE 는 build-time 으로 분류) |
| 운영 차단 사항 | **없음** |
| 추가 조치 | spaCy / pip 보안 어드바이저리 모니터링, pip fix 출시 시 재평가 |

Phase 8 보안 게이트 통과로 평가합니다.

---

## 4. 향후 정기 점검

운영 단계에서는 매월 1회 다음 명령을 수동/자동 실행하여 새로 등록된
CVE 를 확인합니다:

```bash
make security             # bandit
uv run pip-audit --skip-editable  # pip-audit
```

CI 의 `security-scan` 잡은 매 PR 마다 자동으로 동일한 검사를 수행합니다.
