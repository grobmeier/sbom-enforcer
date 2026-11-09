#!/usr/bin/env python3
# Copyright © 2026 Christian Grobmeier
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Exercise release command preconditions without contacting Maven Central."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET


class ReleaseCommandTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'tools').mkdir()
        shutil.copyfile(Path(__file__).with_name('release-to-central.py'), self.root / 'tools/release-to-central.py')
        wrapper = self.root / 'mvnw'
        wrapper.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > invoked-arguments\n')
        wrapper.chmod(0o755)
        for args in [('init', '-q'), ('config', 'user.name', 'Release test'),
                     ('config', 'user.email', 'release@example.invalid'), ('add', '.'),
                     ('-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture')]:
            self.git(*args)
        self.env = dict(os.environ)
        for name in ('CENTRAL_USERNAME', 'CENTRAL_PASSWORD', 'RELEASE_SIGNING_KEY'):
            self.env.pop(name, None)

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.root, check=True, capture_output=True, text=True)

    def invoke(self, *args):
        return subprocess.run(['python3', 'tools/release-to-central.py', *args], cwd=self.root,
                              env=self.env, capture_output=True, text=True)

    def credentials(self):
        self.env.update(CENTRAL_USERNAME='fixture-user', CENTRAL_PASSWORD='fixture-secret',
                        RELEASE_SIGNING_KEY='A' * 40)

    def test_dry_run_does_not_execute_maven(self):
        result = self.invoke('--dry-run', '0.3.0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('-Prelease,central-upload', result.stdout)
        self.assertFalse((self.root / 'invoked-arguments').exists())

    def test_missing_credentials_abort_before_maven(self):
        result = self.invoke('0.3.0')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing environment variables', result.stderr)
        self.assertFalse((self.root / 'invoked-arguments').exists())

    def test_dirty_checkout_aborts_before_maven(self):
        self.credentials()
        (self.root / 'unreviewed').write_text('change')
        result = self.invoke('0.3.0')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('uncommitted or untracked', result.stderr)
        self.assertFalse((self.root / 'invoked-arguments').exists())

    def test_missing_and_mismatched_tag_abort(self):
        self.credentials()
        self.assertNotEqual(self.invoke('0.3.0').returncode, 0)
        self.git('tag', 'sbom-verifier-0.3.0')
        self.git('-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '-qm', 'new revision')
        result = self.invoke('0.3.0')
        self.assertIn('HEAD must match', result.stderr)
        self.assertFalse((self.root / 'invoked-arguments').exists())

    def test_tagged_clean_release_passes_exact_arguments_without_secrets(self):
        self.credentials()
        self.git('tag', 'sbom-verifier-0.3.0')
        result = self.invoke('0.3.0')
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = (self.root / 'invoked-arguments').read_text().splitlines()
        self.assertEqual(arguments, ['-B', '--settings', 'docs/maven-release-settings.xml',
                         '-Prelease,central-upload', '-Drevision=0.3.0', '-Dgpg.keyname=' + 'A' * 40,
                         'clean', 'deploy'])
        self.assertNotIn('fixture-secret', result.stdout + result.stderr + str(arguments))
        self.assertNotIn('fixture-user', result.stdout + result.stderr + str(arguments))

    def test_snapshot_version_is_rejected(self):
        result = self.invoke('--dry-run', '0.3.0-SNAPSHOT')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'invoked-arguments').exists())


class ReleaseProfileTest(unittest.TestCase):
    def test_upload_is_explicit_and_automatic(self):
        root = ET.parse(Path(__file__).resolve().parent.parent / 'pom.xml').getroot()
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
        props = root.find('m:properties', ns)
        self.assertEqual(props.findtext('m:central.skipUpload', namespaces=ns), 'true')
        self.assertEqual(props.findtext('m:central.autoPublish', namespaces=ns), 'false')
        profile = next(p for p in root.findall('m:profiles/m:profile', ns)
                       if p.findtext('m:id', namespaces=ns) == 'central-upload')
        props = profile.find('m:properties', ns)
        self.assertEqual(props.findtext('m:central.skipUpload', namespaces=ns), 'false')
        self.assertEqual(props.findtext('m:central.autoPublish', namespaces=ns), 'true')
        self.assertEqual(props.findtext('m:central.waitUntil', namespaces=ns), 'published')


if __name__ == '__main__':
    unittest.main()
