#!/usr/bin/env python3
"""Generate exact-size synthetic Burp XML without loading the file into RAM.

Examples:
  python large_fixture_generator.py --mib 80 --output /tmp/burp-80.xml
  python large_fixture_generator.py --mib 100 --mode records --body-kib 1024 --output /tmp/burp-100-records.xml
  python large_fixture_generator.py --mib 500 --output /tmp/burp-500.xml
  python large_fixture_generator.py --bytes 524288001 --output /tmp/burp-over-500.xml
  python large_fixture_generator.py --mib 2 --mode cdata --chunk-kib 1024 --output /tmp/burp-cdata.xml
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from decimal import Decimal
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sizes = parser.add_mutually_exclusive_group(required=True)
    sizes.add_argument('--mib', type=Decimal, help='Exact binary MiB size (80, 100, 500, or a decimal)')
    sizes.add_argument('--bytes', type=int, dest='size_bytes', help='Exact bytes; useful for limit +/-1 checks')
    parser.add_argument('--output', type=Path, required=True, help='New output file; existing files are never overwritten')
    parser.add_argument('--mode', choices=('padded', 'records', 'cdata'), default='padded')
    parser.add_argument('--body-kib', type=int, default=1024, help='Response body KiB for records mode (default 1024)')
    parser.add_argument('--padding', choices=('comment', 'whitespace'), default='comment')
    parser.add_argument('--chunk-kib', type=int, default=1024, help='CDATA delimiter boundary KiB')
    args = parser.parse_args()
    if args.mib is not None:
        exact = args.mib * 1024 * 1024
        if not exact.is_finite() or exact != exact.to_integral_value():
            parser.error('--mib must represent a whole number of bytes')
        args.size_bytes = int(exact)
    if args.body_kib <= 0 or args.chunk_kib <= 0:
        parser.error('--body-kib and --chunk-kib must be positive')
    module_path = Path(__file__).resolve().parent / 'tests' / 'large_test_fixtures.py'
    spec = importlib.util.spec_from_file_location('large_test_fixtures', module_path)
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    try:
        result = fixtures.write_fixture(args.output, size_bytes=args.size_bytes, mode=args.mode,
                                        body_bytes=args.body_kib * 1024, padding=args.padding,
                                        cdata_boundary=args.chunk_kib * 1024)
    except (OSError, ValueError) as exc:
        parser.exit(1, str(exc) + '\n')
    manifest_path = args.output.with_suffix(args.output.suffix + '.manifest.json')
    try:
        with manifest_path.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
    except FileExistsError:
        result['manifest_not_saved'] = 'Manifest file already exists; JSON remains available on stdout.'
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
