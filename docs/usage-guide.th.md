# security-skill — คู่มือการใช้งาน

คู่มือแบบ end-to-end สำหรับการใช้งานโปรเจกต์นี้จริง: การติดตั้ง, การเรียกใช้
detector แต่ละตัว, การอ่านผลลัพธ์ (findings), การรัน Policy/Decision/Action
layer, การติดตั้ง AI-agent adapter, และการรัน test suite สำหรับสถาปัตยกรรม
และเหตุผลเชิงออกแบบ ดูที่ `CONTEXT.md`/`plans/` ใน repo security-skill-workspace
— คู่มือนี้ตั้งใจให้เป็นแค่ "จะรันยังไง" ไม่ใช่ "ทำไมถึงออกแบบแบบนี้"

คำสั่งทั้งหมดด้านล่างเขียนโดยอ้างอิงจาก root ของ repo นี้ (`security-skill/`)
English: [`usage-guide.md`](usage-guide.md).

## 1. โปรเจกต์นี้คืออะไร

`security-skill` ทำหน้าที่ security review software artifact ต่างๆ —
source code, IaC, container, Kubernetes manifest, CI/CD pipeline,
dependency, API spec, และ supply-chain metadata — ในแบบเดียวกับที่ security
engineer จริงจะทำ: อ้างอิง OWASP/CWE/NIST-SSDF, แยกแยะ severity/confidence,
และ (เมื่อปลอดภัยพอ) เสนอวิธีแก้ที่เป็นรูปธรรม ออกแบบมาให้ AI coding agent
เรียกใช้ระหว่างการพัฒนา ไม่ใช่รันเป็น standalone scanning service (แต่ทุก
detector ก็เป็น CLI ธรรมดาที่คุณรันเองได้ ซึ่งคือสิ่งที่คู่มือนี้ครอบคลุม)

## 2. การติดตั้ง (Setup)

**ทางลัดที่เร็วที่สุด**: รัน install script ของ repo นี้เอง — จะค้นหาและติดตั้ง
`requirements.txt` จริงทุกไฟล์ใน repo, รัน `npm install` ให้ `detectors/api/`,
และรายงานว่าเครื่องมือภายนอกตัวไหนมี/ไม่มีบน `PATH`:

```
./install.sh              # macOS/Linux
.\install.ps1              # Windows PowerShell / PowerShell Core
install.bat                # Windows cmd.exe
```

ขั้นตอนแบบ manual ด้านล่างคือสิ่งที่ script เหล่านี้ทำให้อัตโนมัตินั่นเอง —
อ่านต่อถ้าอยากทำเองทีละขั้น หรือแค่อยากรู้ว่า detector ตัวไหนต้องการ package อะไร

### 2.1 Python environment

ทุกโมดูลเป็น Python 3 ล้วนๆ เรียกใช้เป็น script ได้เลยโดยไม่ต้องมีขั้นตอน
packaging/install (ไม่มี `pyproject.toml`, ไม่ต้อง `pip install .`) — clone
แล้วรันได้ทันที บาง detector ต้องการ package เพิ่มเติม:

```
pip install -r schema/requirements.txt                  # jsonschema, referencing — ทุกโมดูลที่ validate schema ต้องใช้
pip install -r detectors/code-review/requirements.txt   # semgrep
pip install -r detectors/iac/requirements.txt           # checkov
pip install -r detectors/api/requirements.txt           # PyYAML, ruamel.yaml
pip install -r detectors/supply-chain/requirements.txt  # ruamel.yaml
```

แนะนำ: สร้าง venv เดียวที่ root ของ repo (`python3 -m venv .venv`) แล้ว
ติดตั้งทุกอย่างข้างบนไว้ในนั้น — นี่คือสิ่งที่ `run_all_tests.py` ของ repo นี้
มองหาและใช้เป็นอันดับแรกโดยอัตโนมัติ

### 2.2 เครื่องมือภายนอก (External tools)

detector หลายตัว wrap เครื่องมือ CLI ภายนอกของจริงแทนที่จะเขียนตรรกะ
วิเคราะห์เองใหม่ — ติดตั้งเฉพาะตัวที่ตรงกับประเภท artifact ที่คุณต้องการสแกน:

| เครื่องมือ | ใช้โดย | วิธีติดตั้ง |
|---|---|---|
| `semgrep` | code-review, auth (ครึ่ง JWT) , api (open_redirect) | `pip install semgrep` |
| `trivy` | docker, kubernetes | `brew install trivy` (หรือ prebuilt binary — ดูเอกสารของ trivy เองสำหรับ Windows/Linux) |
| `checkov` | iac, cicd | `pip install checkov` |
| `osv-scanner` | dependency | `brew install osv-scanner` (หรือ prebuilt binary/Scoop/WinGet) |
| `scorecard` | supply-chain (1 ใน 3 check) | `brew install scorecard` |
| `helm` | kubernetes (เฉพาะ check ที่เกี่ยวกับ Helm chart) | ดูเอกสารติดตั้งของ Helm เอง |
| Node.js/npm | api (Spectral spec-lint) | ติดตั้ง Node.js เวอร์ชันปัจจุบันตัวไหนก็ได้ |

ข้อความ error ของแต่ละ detector เองจะบอกคำสั่งติดตั้งที่ถูกต้องเมื่อเครื่องมือ
ของมันหายไป — ไม่ต้องจำตารางนี้ให้ขึ้นใจ detector จะบอกคุณเอง

`detectors/api/` ต้องการ `npm install` ในเครื่องเพิ่มอีกหนึ่งครั้ง:

```
cd detectors/api && npm install
```

### 2.3 ตรวจสอบว่าติดตั้งถูกต้อง

```
python3 run_all_tests.py
```

รัน test suite ทุกตัวใน repo ถ้าติดตั้งสำเร็จควรเห็นเลข `0` ในคอลัมน์ Fail
และ Err ของทุก directory (คอลัมน์ Skip ที่ไม่เป็นศูนย์ถือว่าปกติ — แปลว่า
เครื่องมือภายนอกบางตัวข้างต้นยังไม่ได้ติดตั้ง หรือคุณยังไม่ได้ opt-in
live-network test)

## 3. เริ่มต้นเร็ว — รัน detector ตัวเดียว

detector ทุกตัวรับไฟล์/directory จริงแล้ว print JSON array ของ `Finding`
object (ดู `schema/finding.schema.json`) ออกทาง stdout:

```
python3 detectors/secret/scanner.py path/to/some/file.py
```

```json
[
  {
    "findingId": "secret-...",
    "ruleId": "secret.aws-access-key",
    "title": "Hardcoded AWS access key",
    "severity": "Critical",
    "confidence": 95,
    "problem": "...",
    "impact": "...",
    "recommendation": "...",
    "references": [{"standard": "CWE", "id": "CWE-798"}],
    "location": {"file": "...", "startLine": 12, "endLine": 12},
    "detectorSource": {"name": "secret-detector", "version": "0.1.0"},
    "suppressed": false
  }
]
```

finding ทุกตัวมีรูปแบบเดียวกันไม่ว่าจะมาจาก detector ไหน — นี่คือจุดประสงค์
ของ canonical schema

## 4. sub-skill แต่ละตัว — รันอะไร กับอะไร

| Sub-skill | คำสั่ง | รับอะไรเป็น input |
|---|---|---|
| Secret | `python3 detectors/secret/scanner.py <file> [--artifact-type ...]` | ไฟล์เดียวต่อครั้ง |
| Code Review (injection/SSRF) | `python3 detectors/code-review/scanner.py <file_or_dir> [--config p/owasp-top-ten] [--artifact-type source-code]` | source code |
| Auth (ครึ่ง deterministic) | `python3 detectors/auth/semgrep_detector.py <file_or_dir> [--config p/jwt] [--artifact-type source-code]` | source code |
| Auth (ครึ่ง playbook) | `python3 detectors/auth/playbook.py [--language <lang>]` | print checklist ให้ *คุณ* นำไปใช้เอง — ดู §4.1 |
| Dependency | `python3 detectors/dependency/scanner.py <file_or_dir> [--artifact-type package-lock] [--data-source native]` | project ที่มี lockfile |
| Docker | `python3 detectors/docker/scanner.py <file_or_dir> [--artifact-type dockerfile]` | project ที่มี Dockerfile |
| Kubernetes | `python3 detectors/kubernetes/scanner.py <file_or_dir>` | manifest หรือ Helm chart |
| IaC | `python3 detectors/iac/scanner.py <file_or_dir>` | Terraform/CloudFormation/Ansible |
| API (spec lint) | `python3 detectors/api/scanner.py <spec_path>` | OpenAPI spec |
| API (open redirect) | `python3 detectors/api/open_redirect.py <file_or_dir> [--artifact-type source-code]` | source code |
| API (auth cross-reference) | `python3 detectors/api/crossref.py <spec_path>` | OpenAPI spec |
| CI/CD Pipeline (ครึ่ง deterministic) | `python3 detectors/cicd/scanner.py <file_or_dir>` | repo ที่มี pipeline config |
| CI/CD Pipeline (ครึ่ง playbook) | `python3 detectors/cicd/playbook.py --format <github-actions\|gitlab-ci\|jenkinsfile>` | print checklist — ดู §4.1 |
| Supply Chain (config presence) | `python3 detectors/supply-chain/scanner.py <file_or_dir>` | repo ทั่วไป มักเป็น `.github/workflows/` |
| Supply Chain (SBOM) | `python3 detectors/supply-chain/sbom_scanner.py <file_or_dir>` | repo (ตรวจสอบไฟล์ SBOM ที่เจอ) |
| Supply Chain (Scorecard) | `python3 detectors/supply-chain/scorecard_wrapper.py <file_or_dir>` | root ของ repo |
| Race Condition (TOCTOU) | `python3 detectors/race-condition/playbook.py [--language <lang>]` | print checklist — ดู §4.1 |

### 4.1 sub-skill ที่ใช้ playbook (ครึ่ง playbook ของ Auth, ครึ่ง playbook
ของ CI/CD, Race Condition) ทำงานต่างจากตัวอื่น

sub-skill กลุ่มนี้ไม่ได้สแกนไฟล์แล้ว print finding — แต่ print *checklist*
ออกมาให้มนุษย์หรือ AI agent นำไปใช้พิจารณาโค้ด/config เองโดยตรง เมื่อเจอ
ปัญหาแล้ว ให้สร้าง dict รูปแบบ `Finding` ขึ้นมาเอง แล้ว validate กับ schema:

```python
import playbook   # จาก directory ของ sub-skill นั้นๆ
checklist = playbook.load_checklist()
text = playbook.render_playbook(checklist, language="python")
errors = playbook.validate_agent_finding(my_finding_dict)  # [] ถ้าถูกต้อง
```

ที่ต้องทำแบบนี้เพราะสำหรับ weakness class เฉพาะกลุ่มนี้ ไม่มี deterministic
tool ตัวไหนที่มี coverage คุ้มค่าให้ wrap (ตรวจสอบกับ registry จริงของ
Semgrep แล้วตอน kickoff ของแต่ละ sub-skill) — checklist คือ detector ตัวจริง
ไม่ใช่ทางเลือกสำรอง

## 5. Pipeline เต็ม: Detection → Decision → Policy → Action

ผลลัพธ์ดิบจาก detector ตัวเดียวยังไม่ใช่ `ScanReport` แบบเต็ม
(`schema/scan-report.schema.json`) — การประกอบเป็น ScanReport (เพิ่ม
`schemaVersion`/`scanId`/`repository`/`timestamp`/`summary` ครอบ array
`findings[]`) เป็นหน้าที่ของผู้เรียกใช้เอง ยังไม่มี CLI ตัวเดียวที่ทำให้
อัตโนมัติ เมื่อคุณมี ScanReport แล้ว:

```
# Decision Layer — dedup + การ suppress ตาม org exception
python3 decision/decision.py path/to/scan-report.json [--repo-root path/to/target/repo]

# Policy Engine — severity -> action (block-merge/require-review/create-ticket/notify/none)
python3 policy/engine.py path/to/scan-report.json [--repo-root path/to/target/repo]

# Action Layer: สร้าง Remediation สำหรับ finding เดียว (มีประโยชน์เฉพาะ finding ประเภท secret.* ที่มี patch จริง)
python3 action/remediation.py path/to/finding.json [--source-file path/to/scanned_file]

# Action Layer: gate verdict + payload สำหรับ ticket/notification จาก policy verdict
python3 action/integrations.py path/to/scan-report.json [--repo-root path/to/target/repo]
```

`action/integrations.py` จะ exit ด้วยค่าไม่เป็นศูนย์ก็ต่อเมื่อ
`aggregateAction` ของ policy verdict เป็น `block-merge` — CI step
สามารถใช้ exit code นี้เป็นเงื่อนไข gate ได้โดยตรง

`--repo-root` (รองรับโดย `decision.py`, `policy/engine.py`, และ
`action/integrations.py`) ชี้ไปที่ repo ที่กำลังถูกสแกนจริง เพื่อให้แต่ละตัว
มองหา `.security-skill/exceptions.json` / `.security-skill/policy.json`
ของ repo นั้นเอง — ถ้าไม่ใส่จะใช้ค่า default ที่มากับโปรเจกต์นี้

## 6. Render report เป็น Markdown/HTML

```
python3 schema/render_markdown.py < path/to/scan-report.json > report.md
python3 schema/render_html.py < path/to/scan-report.json > report.html
```

ทั้งสองอ่าน `ScanReport` แบบเต็มจาก stdin (ไม่ใช่แค่ array ของ findings)

ในการ validate `ScanReport` หรือ `Remediation` หรือ `Integration` record
กับ schema โดยตรง:

```
python3 schema/validate.py path/to/scan-report.json
```

## 7. การติดตั้งบน AI agent

ถ้าคุณต้องการให้ AI coding agent เรียกใช้ detector ของโปรเจกต์นี้โดยอัตโนมัติ
ระหว่าง review session ให้ติดตั้ง adapter ที่ตรงกับเครื่องมือของคุณ
**ใช้ symlink ไม่ใช่ copy** ทุกครั้งที่ทำได้ — คำสั่งของทุก adapter อ้างอิง
path แบบ relative จาก root ของ repo นี้เอง; symlink จะยัง resolve ไปที่
checkout จริงได้ แต่ copy จะไม่ได้ และ (จาก manual test ของ plan 017 ที่เจอ
ปัญหานี้จริง) การ copy ยังเสี่ยงที่เนื้อหาจะไม่ sync กับ fix ในอนาคตที่
อาจแก้แค่ที่ checkout จริงที่เดียว `$SECURITY_SKILL` ด้านล่างหมายถึง
absolute path ของ checkout repo นี้บนเครื่องคุณ

### 7.1 Claude Code

เลือกแบบใดแบบหนึ่ง: ระดับ project (เฉพาะผู้ใช้ repo นี้) หรือระดับ personal
(ใช้ได้ทุก repo ที่คุณเปิดใน Claude Code):

```
# ระดับ Project: รันจากภายใน target repo ที่ต้องการ review
mkdir -p .claude/skills
ln -s "$SECURITY_SKILL/adapters/claude-code/security-review" .claude/skills/security-review

# ระดับ Personal: ใช้ได้ทุก repo ที่เปิด
mkdir -p ~/.claude/skills
ln -s "$SECURITY_SKILL/adapters/claude-code/security-review" ~/.claude/skills/security-review
```

**ตรวจสอบ**: เริ่ม session Claude Code ใน target repo แล้วขอให้ทำ security
review — skill ควร trigger เองอัตโนมัติ ถ้าดูเหมือนไม่ทำงาน ให้ตรวจสอบว่า
symlink resolve ถูกต้อง (`ls -la .claude/skills/security-review/SKILL.md`
ควรเห็นเนื้อหาจริง ไม่ใช่ broken link)

### 7.2 Codex / OpenCode / Cursor (convention แบบ AGENTS.md)

ต่างจาก skill directory ที่แยกเดี่ยวของ Claude Code, `AGENTS.md` เป็นไฟล์
เดียวที่ root ของ repo ซึ่งหลาย repo มักมีอยู่แล้วสำหรับ project instruction
ของตัวเอง — ให้ **append** ไม่ใช่เขียนทับ:

```
# รันจากภายใน target repo
cat "$SECURITY_SKILL/adapters/agents-md/AGENTS.md" >> AGENTS.md
```

ถ้า target repo ยังไม่มี `AGENTS.md` คำสั่งนี้จะสร้างให้เอง ถ้ามีอยู่แล้ว
คำสั่งนี้จะ append เนื้อหาส่วน security-review ต่อท้าย — ควรเปิดดูผลลัพธ์
(`AGENTS.md`) สักครั้งเพื่อให้แน่ใจว่าไม่มีอะไรผิดเพี้ยน เพราะ `>>` ธรรมดา
ไม่เข้าใจโครงสร้าง Markdown

**ตรวจสอบ**: ขอให้ agent review ไฟล์ใดไฟล์หนึ่งเพื่อหาปัญหาความปลอดภัย
แล้วยืนยัน (จาก output ของมันเอง หรือใช้เครื่องมืออย่าง `grok inspect`
ของ Grok Build ด้านล่าง) ว่ามันเรียก detector จริงผ่าน Bash จริงๆ ไม่ใช่แค่
วิจารณ์โค้ดจากความรู้ทั่วไป

### 7.3 Antigravity

ใช้ pattern symlink แบบเดียวกับ Claude Code แต่คนละ directory —
Antigravity อ่าน Skill format ของตัวเองจาก `.agents/skills/<name>/`
(หรือ path เก่า `.agent/skills/`):

```
# รันจากภายใน target repo
mkdir -p .agents/skills
ln -s "$SECURITY_SKILL/adapters/antigravity/skills/security-review" .agents/skills/security-review
```

(การรองรับ `AGENTS.md` สำหรับ Antigravity มาจาก §7.2 ข้างบนแล้ว — มันอ่าน
ไฟล์นั้นด้วยตอนเริ่ม session ไม่ต้องทำอะไรเพิ่มสำหรับส่วนนี้)

**ตรวจสอบ**: ยังไม่เคยทดสอบจริงกับ Antigravity ที่ติดตั้งจริงใน development
environment ของโปรเจกต์นี้ (ไม่มี CLI ให้ใช้ในเครื่องที่พัฒนา) — ตรวจสอบว่า
symlink resolve ถูกต้อง แล้วเช็คภายใน Antigravity เองว่า skill ปรากฏใน
listing ของมันหรือไม่

### 7.4 Grok Build

**ไม่ต้องติดตั้งอะไรเลย** Grok Build อ่านทั้ง `AGENTS.md` (§7.2 — ไม่ต้องทำ
อะไรเพิ่มถ้าคุณทำขั้นตอนนั้นไว้แล้วสำหรับเครื่องมืออื่น) และ directory
`.claude/skills/` โดยตรงอยู่แล้ว ยืนยันด้วยการรัน `grok inspect` จริงระหว่าง
พัฒนาโปรเจกต์นี้ (ดู `adapters/grok-build/README.md`) ถ้าคุณติดตั้ง Claude
Code adapter (§7.1) หรือเนื้อหา AGENTS.md (§7.2) ไว้ใน repo แล้ว Grok Build
จะเห็นได้เลยโดยไม่ต้องทำอะไรเพิ่ม

**ตรวจสอบ**:

```
grok inspect
```

มองหา `security-review` ใต้หัวข้อ `Skills` (จะติด tag `project [claude]`
ถ้าเจอ `.claude/skills/security-review/`) และ `AGENTS.md` ของคุณใต้หัวข้อ
`Project Instructions`

### 7.5 กฎเหล็กที่ทุก adapter มีเหมือนกัน

เนื้อหาของทุก adapter ระบุข้อกำหนดเดียวกัน: agent ต้องเรียก detector จริง
และรายงานผลลัพธ์แบบมีโครงสร้างจริง ห้ามใช้วิจารณญาณทั่วไปแทนเมื่อ detector
หรือเครื่องมือที่มันต้องการไม่พร้อมใช้งาน — และถ้าหา checkout ไม่เจอจาก
relative path (เช่นกรณีคุณ copy แทนที่จะ symlink) agent ควรถามคุณว่า
checkout อยู่ที่ไหน แทนที่จะเที่ยวค้นหาใน filesystem เอง

## 8. การรัน test suite

```
python3 run_all_tests.py [--verbose]
```

ค้นหาและรัน `test_*.py` ทุกไฟล์ใน repo ด้วยคำสั่งเดียว พร้อมสรุปผล
pass/fail/skip แยกตาม directory ดู `docs/testing-standards.md` สำหรับ
แนวทาง fixture/mocking/mutation-testing ที่ test ของทุก sub-skill ใช้อยู่
และดู `README.md` ของแต่ละ directory สำหรับคำสั่งตรวจสอบ cross-platform
เฉพาะของ directory นั้น (`LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII
python3 -m unittest ...`)

## 9. การต่อยอดโปรเจกต์นี้

งาน feature ใหม่ใน repo นี้จะถูกวางแผนก่อนแล้วค่อย implement — ดู
`AGENTS.md`/`CONTEXT.md`/`plans/` ใน repo security-skill-workspace
(repo แยกที่ repo นี้เป็น submodule อยู่) สำหรับขั้นตอนการทำงานและ
ประวัติการตัดสินใจเชิงออกแบบทั้งหมดที่อยู่เบื้องหลังคู่มือนี้
