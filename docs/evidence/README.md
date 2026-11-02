# Evidence

Drop captures here as you run `tests/attack/`. Suggested set, in order:

1. `01-before-role.png`: the reporting role with its benign read only policy
2. `02-attack-admin-star.png`: the `put-role-policy` call and its CloudTrail event
3. `03-quarantine-applied.png`: `SentinelQuarantineDenyAll` and the quarantine tags
4. `04-alert-slack.png` and `05-alert-sns.png`
5. `06-dashboard-ttr.png`: the time to remediate widget after several runs
6. `07-s3-before.png`, `08-s3-after.png`: Block Public Access removed, then restored
7. `09-pipeline-gate-fail.png`: a pull request with `Action: "*"` rejected by the OPA gate
8. `10-trail-tamper-alert.png`: the "Audit trail changed: UpdateTrail" alert from `05_trail_tamper.sh`
9. `11-dlq-and-alarms.png`: the CloudWatch alarms list, all in OK after a clean run

Record the seconds to remediate for each run in a small table in the README.
