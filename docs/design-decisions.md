# Design decisions

These are the decisions the code encodes. Each one has a reason and a known cost. Edit this file
as your own thinking changes, because it is the source for the README and the blog post.

## 1. Scope: two incidents, two controls

The brief names two incidents, a public bucket and an over-privileged IAM role. Sentinel has one
control for each, on a shared platform (trail, alert path, dashboard, pipeline gate). The security
group control from `config-auto-revoke-sg` is not in scope because the brief does not ask for it.

## 2. Home region is us-east-1

IAM is a global service and its CloudTrail events are only delivered to us-east-1. The IAM rule
must live there, so the whole platform does too. `envs/dev/variables.tf` enforces it.

Extending to more regions: the S3 rule needs to exist in every region that holds buckets, because
bucket level API calls reach EventBridge in the bucket's region. The clean way is to forward those
events to a central bus in us-east-1 with a rule per region, or to deploy the responder module per
region with the same source package. Not built here. Say so in the README.

## 3. Quarantine, not revert

On a violation Sentinel attaches an inline deny and tags the role. It does not remove the grant.

* Evidence is preserved exactly as the attacker left it.
* A revert can break a legitimate workload on a false positive. A quarantine can too, but it is
  undone by deleting one policy, with nothing to reconstruct.
* The cost is that the dangerous grant stays attached. The runbook says to remove it before lifting
  the quarantine, and Sentinel re-quarantines the next time the role changes if the grant is still there.

## 4. Two response tiers

| Finding | Response |
|---|---|
| `Action: "*"` or `NotAction` on `Resource: "*"` | Deny all |
| Trust policy open to any principal or an unlisted account | Deny all |
| `service:*` on `Resource: "*"` (for example `rds:*`) | Targeted deny of data exfiltration actions |

For `rds:*` a full deny would break a read only reporting role. The targeted deny blocks snapshot
creation, copy, sharing and export, and leaves `rds:Describe*` working. The action list lives in
`src/iam_quarantine/policy_eval.py` (`EXFIL_ACTIONS`) and is maintained by hand. A service that is
not in the list falls back to denying `service:*`.

Known cost: a targeted deny does not stop destructive calls such as deleting a database. Whether
that is acceptable is a judgment call to make and defend.

## 5. Live state evaluation, not event parsing

Every invocation reads the role as it exists now: trust policy, inline policies, and attached managed
policies at their default version. It never trusts the event to describe the violation. Reasons:

* A `CreatePolicyVersion` on a managed policy changes permissions with no attachment event at all.
  The handler finds the roles using that policy and evaluates each one.
* Sentinel's own quarantine call raises another IAM event. The second invocation sees a role that is
  already covered and exits with "no action needed". It is also skipped earlier because the actor is
  Sentinel's own role. Both guards exist on purpose.

## 6. Authorized change versus drift (the hard question)

The pipeline legitimately changes IAM, so Sentinel must not quarantine its own deployments.

Chosen approach: an explicit list of authorized actor ARNs (`authorized_actor_arns`). A violating
change by a listed actor is not quarantined but still raises a warning alert and an `ExemptViolation`
metric.

What this trusts: the deploy role. An attacker who assumes that role is invisible to Sentinel's
quarantine. Mitigations in this repo:

* The deploy role can only be assumed by a job in the protected GitHub environment (OIDC `sub` claim),
  so a pull request can never get it.
* The OPA gate rejects `Allow *` on `*` before the deploy role ever creates it.
* The deploy role has an explicit deny on attaching `AdministratorAccess`.
* Exempt violations still alert.

Not built, worth discussing: require web identity session data on exempt changes, compare the changed
policy to the Terraform plan hash, or move enforcement to an SCP.

## 7. Scope of protection is a tag

Only roles tagged `sentinel:protected=true` are touched. This is enforced twice: in the handler, and
by the Lambda's IAM policy, which can only call `PutRolePolicy` and `TagRole` on roles with that tag.
A compromised Sentinel cannot quarantine, or attach new permissions to, arbitrary roles.

Roles enter scope through `CreateRole` (born protected) or `TagRole` (an existing role tagged later).
Both events are watched, so a role that already violates is quarantined the moment it becomes protected.

Known gap: removing the `sentinel:protected` tag takes a role out of scope, and Sentinel can no
longer write to it. The handler alerts critically and emits `CriticalViolation`, so the CloudWatch
alarm fires too, but it cannot remediate. Closing the gap properly needs an SCP that denies
`iam:UntagRole` on `sentinel:*` keys except for release principals. When a release principal removes
the tag, it is recorded as `QuarantineReleased` with an info alert, not treated as an attack.

## 8. Quarantine tamper protection

Deleting `SentinelQuarantine*` or removing the `sentinel:quarantined` tag is itself an event Sentinel
watches. An unauthorized removal is restored with a deny all. Release principals
(`release_principal_arns`) can lift a quarantine, and the lift is recorded and alerted.

## 9. Secrets

The Slack webhook is in Secrets Manager. Terraform creates the empty secret and never the value, and
an OPA rule blocks `aws_secretsmanager_secret_version` outright, so the value cannot land in state.
The Lambda reads it at runtime with `GetSecretValue` scoped to that one secret ARN, and only posts to
URLs beginning `https://hooks.slack.com/`.

## 10. Observability

Metrics are CloudWatch Embedded Metric Format lines inside the structured log output, so the Lambdas
need no `PutMetricData` permission. `TimeToRemediateSeconds` is measured from the CloudTrail `eventTime`,
which includes CloudTrail to EventBridge delivery latency. That is the honest end to end number.

Alerts take two independent paths: the Lambda publishes to SNS and Slack directly, and CloudWatch
alarms on `CriticalViolation`, `RemediationFailed`, `AlertFailed`, Lambda errors and dead letter queue
depth publish to the same topic. If a Lambda dies, the alarms still fire.

Every critical path emits `CriticalViolation`: an exposed bucket, a deny all quarantine, quarantine
tampering, and removal of the protection tag. Exempt violations (an authorized actor on IAM, or a
`sentinel:public-allowed` bucket that is actually missing Block Public Access) emit `ExemptViolation`,
so allowed-by-design exposure is still a visible trend on the dashboard.

The Slack webhook is cached only once it is valid. If the secret is still empty, the next alert
tries again, so setting the secret after deploy takes effect without a cold start.

## 12. Nothing is dropped silently between detection and response

Each detection rule has a retry policy and a dead letter config on its EventBridge target, and the
Lambda has its own async DLQ. Both point at the same CMK encrypted queue. The queue policy only
accepts messages from that control's rule (`aws:SourceArn`). So an event lands in the DLQ whether
EventBridge could not deliver it or the function failed every retry, and the DLQ alarm fires either way.

## 13. Watching the watcher

If someone can stop the trail, every control goes blind. A third EventBridge rule, alert only, goes
straight to SNS with no Lambda in the path. It watches `StopLogging`, `DeleteTrail`, `UpdateTrail` and
`PutEventSelectors` on CloudTrail, plus policy and lifecycle changes on the log bucket. It is
deliberately not a third control: it does not call `StartLogging`, because an attacker who can stop
logging can also stop it again, and the right response is a human. Terraform applies that touch the
trail trigger it too. That is intended, because trail changes should always be seen.

## 14. The plan gate and values that are unknown until apply

On a first deploy, KMS key ARNs and IAM policies built from not yet existing ARNs are unknown in the
plan JSON (`after_unknown`). The OPA rules treat an unknown KMS attribute as set, because the module
always passes a key. They raise a `warn` for an unknown IAM policy instead of silently passing it.
Those policies are evaluated on every later plan once the ARNs exist, and Checkov and Trivy check
the source on every pull request.

The gate also rejects trust policies open to `*`, SQS queues without the CMK, and Lambdas without
active X-Ray tracing.

## 15. The deploy role is scoped, not trusted

`bootstrap/oidc.tf` lists explicit S3 write actions instead of `s3:*`. KMS key creation requires the
`Project` request tag, and key management requires the `Project` resource tag. An explicit deny stops
the pipeline from changing the policy of, or deleting, the Terraform state key. The PR plan and the
deploy plan use identical inputs (`TF_VAR_*` from repository variables), so the plan OPA reviews on a
pull request is the plan that is later applied.

## 11. Things this repo does not do

* Multi region S3 detection (see decision 2).
* Account level Block Public Access (`PutAccountPublicAccessBlock`) is not watched. The controls work
  bucket by bucket. Turning account level BPA on is a sensible extra guard outside Sentinel.
* No automatic restart of a stopped trail (see decision 13).
* Conditions are ignored when judging a broad grant, so a conditioned `Action: "*"` is still flagged.
  That produces false positives. The authorized actor list is the release valve.
* No object level inspection of bucket contents, only the exposure settings.
