# Cursor Cloud Review

This tool allows you to trigger a Cursor Cloud agent review for an active pull request. It analyzes the changes in the pull request and provides a detailed report on security, correctness, and reliability.

## Installation

```bash
pip install cursor-cloud-review
```

## Usage

You need to set the `CURSOR_CLOUD_API_KEY` environment variable.

```bash
export CURSOR_CLOUD_API_KEY=your_api_key
cursor-cloud-review --repo-url https://github.com/owner/repo --pr-number 123
```

### Arguments

- `--repo-url`: Full URL of the repository (e.g., https://github.com/OWNER/REPO).
- `--pr-number`: The pull request number.
- `--base-ref`: Base branch ref name (optional).
- `--base-sha`: Base commit SHA (optional).
- `--head-ref`: Head branch ref name (optional).
- `--head-sha`: Head commit SHA (optional).
- `--analysis-report`: Path to the markdown report output (default: `cursor-cloud-analysis.md`).
- `--metadata-out`: Path to the metadata JSON output (default: `cursor-cloud-analysis.json`).
- `--base-url`: Cursor Cloud API base URL (default: `https://api.cursor.com`).
- `--api-key`: Cursor Cloud API key (can also be set via `CURSOR_CLOUD_API_KEY`).

## License

MIT
