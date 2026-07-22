# IaC — reference

Terraform, CloudFormation, Ansible.

## Command

```
python3 detectors/iac/scanner.py path/to/project
```

## Prerequisite

Requires the real `checkov` CLI on `PATH` (`pip install -r
requirements.txt` in `detectors/iac/`, or `pip install checkov`
directly). If missing, relay the error verbatim per `SKILL.md`'s hard
rule.

## Output

A JSON array of `Finding` objects on stdout (`ruleId` prefix `iac.*`).
Report each one per `SKILL.md`'s Step 2.
