#!/usr/bin/env python3
"""Trigger a Cursor Cloud agent review for the active pull request."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

DEFAULT_BASE_URL = "https://api.cursor.com"
POLL_INTERVAL_SECONDS = 10
MAX_WAIT_SECONDS = 900
MAX_CHANGED_FILES = 200


def run_command(args: List[str]) -> str:
    """Run a shell command and return stdout (raises on failure)."""
    result = subprocess.run(args, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command {' '.join(args)} failed (exit {result.returncode}):\n{result.stderr.strip()}"
        )
    return result.stdout.strip()


def gather_changed_files(base_ref: Optional[str], head_ref: Optional[str]) -> List[str]:
    """Return a sorted list of files changed between base and head."""
    if not head_ref:
        head_ref = "HEAD"
    diff_range = head_ref if not base_ref else f"{base_ref}...{head_ref}"
    output = run_command(["git", "diff", "--name-only", diff_range])
    files = [line.strip() for line in output.splitlines() if line.strip()]
    unique_files = sorted(dict.fromkeys(files))
    return unique_files[:MAX_CHANGED_FILES]


def build_prompt(
    repo_url: str,
    pr_number: str,
    base_ref: Optional[str],
    base_sha: Optional[str],
    head_ref: Optional[str],
    head_sha: Optional[str],
    changed_files: List[str],
) -> str:
    files_section = "\n".join(f"- {path}" for path in changed_files) or "(Git diff empty)"
    prompt = f"""
You are Cursor Cloud GPT-5.1 Codex acting as a senior security and reliability
engineer. Perform a holistic analysis of the repository with an emphasis on the
current pull request.

Repository: {repo_url}
Pull Request: #{pr_number}
Head: {head_ref or 'HEAD'} ({head_sha or 'unknown'})
Base: {base_ref or 'auto-detected merge-base'} ({base_sha or 'unknown'})

Changed files that must be prioritized:
{files_section}

Objectives:
1. Scrutinize the entire codebase (not only the diff) for correctness, security
   regressions, data-leak vectors, and reliability gaps relevant to this PR.
2. Highlight high-impact issues first (critical security bugs, data loss, RCE,
   privilege escalation, auth bypass, misconfiguration, or broken invariants).
3. For each finding, include:
   - File path(s) and function/class if identifiable
   - Severity (Critical/High/Medium/Low)
   - Technical rationale referencing concrete code
   - Remediation guidance
4. Summarize positive assurances if no blockers exist, but never omit risks.
5. Do not modify code or create commits/PRs. Produce a Markdown report only.

Deliverable: Markdown with sections for Summary, Critical Findings, High
Findings, Additional Observations, and Suggested Follow-up Tests.
"""
    return textwrap.dedent(prompt).strip()


def create_agent(
    base_url: str,
    api_key: str,
    repo_url: str,
    repo_ref: Optional[str],
    prompt: str,
) -> str:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "cursor-cloud-review-script/1.0",
    }
    payload: Dict[str, Any] = {
        "prompt": {"text": prompt},
        "source": {
            "repository": repo_url,
            "ref": repo_ref or "HEAD",
        },
    }
    response = requests.post(
        f"{base_url.rstrip('/')}/v0/agents",
        headers=headers,
        json=payload,
        timeout=120,
    )
    if response.status_code >= 400:
        raise RuntimeError(
            f"Cursor Cloud agent creation failed ({response.status_code}): {response.text}"
        )
    data = response.json()
    agent_id = str(data.get("id") or data.get("agent_id") or data.get("agent", {}).get("id"))
    if not agent_id:
        raise RuntimeError(f"Unable to extract agent id from response: {json.dumps(data)[:400]}")
    return agent_id


def wait_for_report(
    base_url: str,
    api_key: str,
    agent_id: str,
    *,
    poll_interval: int = POLL_INTERVAL_SECONDS,
    timeout_seconds: int = MAX_WAIT_SECONDS,
) -> Dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "cursor-cloud-review-script/1.0",
    }
    start = time.time()
    while True:
        response = requests.get(
            f"{base_url.rstrip('/')}/v0/agents/{agent_id}", headers=headers, timeout=60
        )
        if response.status_code >= 400:
            raise RuntimeError(
                f"Failed to fetch agent status ({response.status_code}): {response.text}"
            )
        payload = response.json()
        status = (payload.get("status") or payload.get("state") or "").upper()
        if status in {"FINISHED", "COMPLETED", "DONE", "SUCCESS", "EXPIRED"}:
            return payload
        if status in {"FAILED", "ERROR"}:
            raise RuntimeError(
                f"Cursor Cloud agent exited with status {status}: {payload.get('error') or payload}"
            )
        if time.time() - start > timeout_seconds:
            raise TimeoutError(
                f"Cursor Cloud agent {agent_id} did not finish within {timeout_seconds}s"
            )
        time.sleep(poll_interval)


def extract_markdown(status_payload: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """Return (markdown_report, optional_pr_url)."""
    report = status_payload.get("report")
    markdown: Optional[str] = None
    if isinstance(report, dict):
        markdown = report.get("markdown") or report.get("text")
    elif isinstance(report, str):
        markdown = report
    if not markdown:
        outputs = status_payload.get("output") or {}
        if isinstance(outputs, dict):
            markdown = outputs.get("markdown") or outputs.get("text")
    if not markdown:
        messages = status_payload.get("messages") or []
        if isinstance(messages, list):
            collected = []
            for message in messages:
                if isinstance(message, dict):
                    text = message.get("text") or message.get("markdown")
                    if text:
                        collected.append(str(text))
            if collected:
                markdown = "\n\n".join(collected)
    if not markdown:
        markdown = f"`Cursor Cloud returned no markdown output. Raw payload:`\n\n````json\n{json.dumps(status_payload, indent=2)[:6000]}\n````"
    pr_url: Optional[str] = None
    target = status_payload.get("target")
    if isinstance(target, dict):
        pr_url = target.get("prUrl") or target.get("pr_url")
    return markdown, pr_url


def write_report(report_path: Path, metadata_path: Path, markdown: str, meta: Dict[str, Any]) -> None:
    report_path.write_text(markdown, encoding="utf-8")
    metadata = {"report_path": str(report_path), **meta}
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Trigger Cursor Cloud agent review")
    parser.add_argument("--repo-url", required=True, help="Full https://github.com/OWNER/REPO URL")
    parser.add_argument("--pr-number", required=True, help="Pull request number")
    parser.add_argument("--base-ref", help="Base branch ref name")
    parser.add_argument("--base-sha", help="Base commit SHA")
    parser.add_argument("--head-ref", help="Head branch ref name")
    parser.add_argument("--head-sha", help="Head commit SHA")
    parser.add_argument("--analysis-report", default="cursor-cloud-analysis.md", help="Path to markdown report")
    parser.add_argument("--metadata-out", default="cursor-cloud-analysis.json", help="Path to metadata JSON")
    parser.add_argument("--base-url", default=os.getenv("CURSOR_CLOUD_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--api-key", default=os.getenv("CURSOR_CLOUD_API_KEY"), help="Cursor Cloud API key")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.api_key:
        print("[cursor-cloud] CURSOR_CLOUD_API_KEY is required", file=sys.stderr)
        return 1
    report_path = Path(args.analysis_report)
    metadata_path = Path(args.metadata_out)

    changed_files = gather_changed_files(args.base_sha or args.base_ref, args.head_sha or args.head_ref)
    prompt = build_prompt(
        repo_url=args.repo_url,
        pr_number=args.pr_number,
        base_ref=args.base_ref,
        base_sha=args.base_sha,
        head_ref=args.head_ref,
        head_sha=args.head_sha,
        changed_files=changed_files,
    )
    print("[cursor-cloud] Launching agent against", args.repo_url)
    agent_id = create_agent(
        base_url=args.base_url,
        api_key=args.api_key,
        repo_url=args.repo_url,
        repo_ref=args.head_ref or args.head_sha,
        prompt=prompt,
    )
    print(f"[cursor-cloud] Agent {agent_id} created. Waiting for completion...")
    status_payload = wait_for_report(args.base_url, args.api_key, agent_id)
    markdown, pr_url = extract_markdown(status_payload)

    summary_header = textwrap.dedent(
        f"""
        # 🤖 Cursor Cloud Agent Report
        *Repository:* {args.repo_url}
        *Pull Request:* #{args.pr_number}
        *Agent ID:* {agent_id}
        *Evaluated Commit:* {args.head_sha or 'HEAD'}
        """
    ).strip()
    final_report = f"{summary_header}\n\n{markdown.strip()}\n"

    write_report(
        report_path=report_path,
        metadata_path=metadata_path,
        markdown=final_report,
        meta={
            "agent_id": agent_id,
            "pr_url": pr_url,
            "status": status_payload.get("status") or status_payload.get("state"),
            "changed_files": changed_files,
        },
    )
    print(f"[cursor-cloud] Analysis written to {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
