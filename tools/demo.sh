#!/usr/bin/env bash
curl -s -X POST http://127.0.0.1:8000/triage \
  -H "content-type: application/json" \
  -d @data/samples/telemetry.json | jq .
