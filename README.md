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

### GitHub Actions

You can integrate this tool into your GitHub workflow to automatically review pull requests.

**Prerequisites:**
1.  Obtain your `CURSOR_CLOUD_API_KEY`.
2.  Add it to your repository secrets: `Settings` > `Secrets and variables` > `Actions` > `New repository secret`. Name it `CURSOR_CLOUD_API_KEY`.

**Example Workflow:**

Create a file named `.github/workflows/cursor-review.yml`:

```yaml
name: Cursor Cloud Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read

    steps:
      - name: Checkout repository
        uses: actions/checkout@v3
        with:
          # Important: Fetch full history so that git diff can identify changes against the base branch
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install cursor-cloud-review
        run: pip install cursor-cloud-review

      - name: Run Cursor Cloud Review
        env:
          CURSOR_CLOUD_API_KEY: ${{ secrets.CURSOR_CLOUD_API_KEY }}
        run: |
          cursor-cloud-review \
            --repo-url "${{ github.server_url }}/${{ github.repository }}" \
            --pr-number "${{ github.event.pull_request.number }}" \
            --base-ref "origin/${{ github.base_ref }}" \
            --head-ref "HEAD"
```

The tool will generate a `cursor-cloud-analysis.md` file containing the review. You can add additional steps to this workflow to post the content of this file as a comment on the PR or upload it as an artifact.

### Arguments

- `--repo-url`: Full URL of the repository (e.g., https://github.com/OWNER/REPO).
- `--pr-number`: The pull request number.
- `--base-ref`: Base branch ref name (optional).
- `--base-sha`: Base commit SHA (optional).
- `--head-ref`: Head branch ref name (optional).
- `--head-sha`: Head commit SHA (optional).
- `--analysis-report`: Path to the markdown report output (default: `cursor-cloud-analysis.md`).
- `--metadata-out`: Path to the metadata JSON output (default: `cursor-cloud-analysis.json`).
- `--base-url`: Cursor Cloud API base URL (default: `https://api.cursor.com`, or via `CURSOR_CLOUD_BASE_URL`).
- `--api-key`: Cursor Cloud API key (can also be set via `CURSOR_CLOUD_API_KEY`).

**Note:** The tool will prioritize the first 200 changed files for analysis. The agent execution has a timeout of 15 minutes.

## License

MIT
