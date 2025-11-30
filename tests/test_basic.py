import unittest
from unittest.mock import patch, MagicMock
import sys
from io import StringIO
from cursor_cloud_review.cli import parse_args, build_prompt

class TestCursorCloudReview(unittest.TestCase):
    def test_parse_args(self):
        test_args = [
            "--repo-url", "https://github.com/owner/repo",
            "--pr-number", "123",
            "--api-key", "fake-key"
        ]
        with patch.object(sys, 'argv', ["prog"] + test_args):
            args = parse_args()
            self.assertEqual(args.repo_url, "https://github.com/owner/repo")
            self.assertEqual(args.pr_number, "123")
            self.assertEqual(args.api_key, "fake-key")

    def test_build_prompt(self):
        prompt = build_prompt(
            repo_url="https://github.com/owner/repo",
            pr_number="123",
            base_ref="main",
            base_sha="sha1",
            head_ref="feature",
            head_sha="sha2",
            changed_files=["file1.py", "file2.py"]
        )
        self.assertIn("Repository: https://github.com/owner/repo", prompt)
        self.assertIn("Pull Request: #123", prompt)
        self.assertIn("- file1.py", prompt)
        self.assertIn("- file2.py", prompt)

if __name__ == "__main__":
    unittest.main()
