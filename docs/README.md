# Documentation

This directory contains operational and reference documentation for
mcp-gateway.

## Guides

| Document | Purpose |
|----------|---------|
| [Operations Guide](operations.md) | Start/stop procedures, health checks, structured logs, troubleshooting, and deployment migration notes. |
| [Configuration Reference](configuration.md) | Environment variables, `config.yaml`, route syntax, token persistence, reverse proxy settings, and endpoint reference. |
| [v0.1.0 E2E Runbook](runbook-e2e-v0.1.0.md) | End-to-end acceptance runbook for setup wizard, encryption, routing, token persistence, and device flow. |
| [Copilot API Auth Spike](spike-18-copilot-api-auth.md) | Investigation notes for the Copilot API upstream authentication model. |

## Examples

| Path | Purpose |
|------|---------|
| [`../examples/copilot-review-routing/`](../examples/copilot-review-routing/) | Docker Compose example for routing both `github-mcp-server` and `copilot-review-mcp` through one gateway. |

## README Split

The root [README](../README.md) is intentionally focused on the first-run path,
architecture overview, and links into these documents. Detailed configuration
and operations material should live here to keep the README scannable.
