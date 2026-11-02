# Runbook: responding to a Sentinel quarantine

## An IAM role was quarantined

1. Read the alert. It names the role, the actor, the source IP, the event time and the event ID.
2. Treat the actor as suspect until proven otherwise. Look up the event ID in CloudTrail.
3. Look at the role: `aws iam list-role-policies` and `aws iam list-attached-role-policies`.
   The `SentinelQuarantine*` policy is Sentinel's. Everything else is what the attacker left.
4. **Remove the offending grant first.** Detach the managed policy or delete the inline policy,
   or restore the trust policy.
5. Only then lift the quarantine, using a break glass role listed in `release_principal_arns`:
   delete the `SentinelQuarantine*` inline policy, then remove the `sentinel:quarantine*` tags.
6. If you lift it while the grant is still attached, Sentinel quarantines the role again at the next
   IAM change on it. That is the intended safety net.

If someone else removes the quarantine, Sentinel puts a deny all back and raises a critical alert.

## A bucket was secured

Sentinel enabled Block Public Access on all four settings and tagged the bucket
`sentinel:quarantined=true`. The public policy or ACL is still there, but now inert.
Find the actor in the alert, decide whether the change was intended, then fix the root cause.
If the bucket is meant to be public, tag it `sentinel:public-allowed=true` and re-apply the change.

## The audit trail was changed

The alert title is `Audit trail changed: <event>`. Treat `StopLogging`, `DeleteTrail` and
`DeleteBucketPolicy` on the log bucket as an active incident: every Sentinel control depends on the trail.

1. Check the trail is still logging: `aws cloudtrail get-trail-status --name <trail_arn output>`.
2. If it is not, run `aws cloudtrail start-logging --name <trail_arn>`, then run `terraform apply`
   from `envs/dev` to restore the event selectors and the bucket policy exactly as defined.
3. Investigate the actor and source IP in the alert. Assume they also tried something else while
   the trail was blind, so review IAM and S3 changes in the gap by hand.

If the actor is the CI deploy role and the time matches a pipeline run, it was a Terraform apply.

## Sentinel failed

* `RemediationFailed` alarm: the Lambda detected a violation and could not fix it. Act manually now.
* DLQ alarm: an event could not be delivered or failed all retries. Read the message from the
  `<control>-dlq` queue, fix the cause, and replay it by invoking the function with the message body.
* Lambda errors alarm: read the function's log group.
* `alert-delivery-failed` alarm: the remediation ran, but SNS or Slack rejected the alert. Check the
  function log for `sns publish failed` or `slack post failed`. The usual cause for Slack is an
  expired webhook. Rotate it with `aws secretsmanager put-secret-value`. No redeploy is needed.

## A role lost its protected tag

Sentinel can only alert. Re-add `sentinel:protected=true` once you have confirmed the change was
unintended, and review the role by hand because Sentinel has not. Re-adding the tag is itself a
`TagRole` event, so Sentinel re-evaluates the role straight away and quarantines it if it still violates.

If a release principal removed the tag, you get an info alert ("Protection removed ... by release
principal") instead. That is a recorded, intended release.
