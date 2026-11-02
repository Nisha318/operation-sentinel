"""Structured logging plus CloudWatch Embedded Metric Format (EMF) metrics.

Every action Sentinel takes is one JSON line. Metrics ride along in the same log
line, so no cloudwatch:PutMetricData permission is needed.
"""

import json
import time

NAMESPACE = "Sentinel"


def log(level, message, **fields):
    record = {"level": level, "message": message}
    record.update(fields)
    print(json.dumps(record, default=str))


def emit_metric(control, name, value=1, unit="Count"):
    record = {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": NAMESPACE,
                    "Dimensions": [["Control"]],
                    "Metrics": [{"Name": name, "Unit": unit}],
                }
            ],
        },
        "Control": control,
        name: value,
        "message": f"metric {name}",
        "level": "info",
    }
    print(json.dumps(record, default=str))
