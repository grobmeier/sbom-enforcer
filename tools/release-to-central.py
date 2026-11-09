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

"""Publish an approved tagged release through Maven Central. Use --dry-run to print the plan."""
import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version')
    parser.add_argument('--dry-run', action='store_true', help='Print the release plan without running Maven or uploading files.')
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', args.version):
        parser.error('Use a release version such as 0.3.0.')
    root = Path(__file__).resolve().parent.parent
    tag = f'sbom-verifier-{args.version}'
    key = os.environ.get('RELEASE_SIGNING_KEY', '')
    command = ['./mvnw', '-B', '--settings', 'docs/maven-release-settings.xml',
               '-Prelease,central-upload', f'-Drevision={args.version}',
               '-Dgpg.keyname=' + (key if not args.dry_run else '<RELEASE_SIGNING_KEY>'), 'clean', 'deploy']
    if args.dry_run:
        print(f'Require a clean checkout at tag {tag}, reviewed CI, and an unlocked published signing key.')
        print('Require CENTRAL_USERNAME, CENTRAL_PASSWORD, and RELEASE_SIGNING_KEY in the environment.')
        print('On an approved invocation, Maven uploads, validates, publishes, and waits for publication.')
        print(shlex.join(command))
        print('Dry run: no Maven command was executed and no files were uploaded.')
        return 0
    missing = [name for name in ('CENTRAL_USERNAME', 'CENTRAL_PASSWORD', 'RELEASE_SIGNING_KEY')
               if not os.environ.get(name)]
    if missing:
        parser.error('Missing environment variables: ' + ', '.join(missing))
    if not re.fullmatch(r'[0-9a-fA-F]{40}|[0-9a-fA-F]{64}', key):
        parser.error('RELEASE_SIGNING_KEY must contain the full signing key fingerprint.')
    def git(*arguments):
        return subprocess.check_output(['git', *arguments], cwd=root, text=True).strip()
    if git('status', '--porcelain'):
        parser.error('The release checkout has uncommitted or untracked files.')
    try:
        target = git('rev-parse', '--verify', f'refs/tags/{tag}^{{commit}}')
    except subprocess.CalledProcessError:
        parser.error(f'The release tag {tag} does not exist.')
    if target != git('rev-parse', 'HEAD'):
        parser.error(f'HEAD must match the release tag {tag}.')
    return subprocess.run(command, cwd=root, check=False).returncode


if __name__ == '__main__':
    raise SystemExit(main())
