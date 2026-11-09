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

"""Verify local release artifacts and assemble a ZIP. This script has no upload operation."""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET
from zipfile import ZIP_DEFLATED, ZipFile


def prepare(target, version, fingerprint, output):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('Use a release version such as 0.3.0.')
    fingerprint = fingerprint.upper()
    if not re.fullmatch(r'[0-9A-F]{40}|[0-9A-F]{64}', fingerprint):
        raise ValueError('Supply the full release signing key fingerprint.')
    artifact = 'sbom-verifier-maven-plugin'
    base = f'{artifact}-{version}'
    files = {f'{base}{suffix}': target / f'{base}{suffix}'
             for suffix in ('.pom', '.jar', '-sources.jar', '-javadoc.jar')}
    files.update({f'{base}-cyclonedx.{ext}': target / f'bom.{ext}' for ext in ('xml', 'json')})
    ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
    pom = ET.parse(files[f'{base}.pom']).getroot()
    for field, value in (('groupId', 'de.grobmeier'), ('artifactId', artifact), ('version', version)):
        if pom.findtext(f'm:{field}', namespaces=ns) != value:
            raise ValueError(f'The candidate POM has an incorrect {field}.')
    for field in ('name', 'description', 'url', 'licenses/license', 'developers/developer', 'scm/url'):
        if pom.find('m:' + field.replace('/', '/m:'), ns) is None:
            raise ValueError(f'The candidate POM is missing {field}.')
    if pom.find('m:parent', ns) is not None or 'SNAPSHOT' in ET.tostring(pom, encoding='unicode'):
        raise ValueError('The candidate POM must be flattened and contain no SNAPSHOT references.')
    with ZipFile(files[f'{base}.jar']) as jar:
        descriptor = ET.fromstring(jar.read('META-INF/maven/plugin.xml'))
        if (descriptor.findtext('groupId'), descriptor.findtext('artifactId'),
                descriptor.findtext('version'), descriptor.findtext('goalPrefix')) != (
                'de.grobmeier', artifact, version, 'sbom-verifier'):
            raise ValueError('The plugin descriptor does not match the release coordinates.')
    for suffix in ('-sources.jar', '-javadoc.jar'):
        with ZipFile(files[base + suffix]) as jar:
            if not any(n.endswith('.java' if suffix == '-sources.jar' else '.html') for n in jar.namelist()):
                raise ValueError(f'{suffix} has no expected content.')
    entries = {}
    for name, path in files.items():
        signature = Path(str(path) + '.asc')
        if not signature.is_file():
            raise ValueError(f'Missing signature: {signature}')
        result = subprocess.run(['gpg', '--batch', '--no-auto-key-retrieve', '--status-fd', '1',
                                 '--verify', str(signature), str(path)], capture_output=True, text=True)
        valid = [line.split()[2:] for line in result.stdout.splitlines()
                 if line.startswith('[GNUPG:] VALIDSIG ')]
        if result.returncode or not any(fingerprint in (row[0], row[-1]) for row in valid):
            raise ValueError(f'{name} is not signed by the specified release key.')
        data = path.read_bytes()
        entries[name] = data
        entries[name + '.asc'] = signature.read_bytes()
        for algorithm in ('md5', 'sha1', 'sha256', 'sha512'):
            entries[name + '.' + algorithm] = hashlib.new(algorithm, data).hexdigest().encode('ascii')
    output.parent.mkdir(parents=True, exist_ok=True)
    prefix = f'de/grobmeier/{artifact}/{version}/'
    with ZipFile(output, 'w', ZIP_DEFLATED) as archive:
        for name, data in sorted(entries.items()):
            archive.writestr(prefix + name, data)
    print(f'Verified six artifacts and signatures. Created {output} with {len(entries)} files.')
    print('No files were uploaded.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--signing-fingerprint', required=True)
    parser.add_argument('--target', type=Path, default=Path('maven-plugin/target'))
    parser.add_argument('--output', type=Path, default=Path('maven-plugin/target/release/central-bundle.zip'))
    args = parser.parse_args()
    try:
        prepare(args.target, args.version, args.signing_fingerprint, args.output)
    except (ValueError, OSError, ET.ParseError) as error:
        parser.exit(1, f'Bundle preparation failed: {error}\n')
