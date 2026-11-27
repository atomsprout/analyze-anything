#!/usr/bin/env python3
"""Compare MSI declarations and Binary streams through read-only Windows Installer APIs.

The analyzer is run separately. This development reference never installs, launches,
loads or administratively extracts the supplied package.
"""
import argparse
import ctypes
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path
import sys

TABLES = {
    'CustomAction': [('Action', 's'), ('Type', 'i'), ('Source', 's'), ('Target', 's')],
    'LaunchCondition': [('Condition', 's'), ('Description', 's')],
    'Binary': [('Name', 's'), ('Data', 'b')],
    **{name: [('Action', 's'), ('Condition', 's'), ('Sequence', 'i')] for name in
       ('InstallExecuteSequence', 'InstallUISequence', 'AdminExecuteSequence', 'AdminUISequence', 'AdvtExecuteSequence')},
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Installer:
    def __init__(self, path):
        self.api = ctypes.WinDLL('msi')
        signatures = {
            'MsiOpenDatabaseW': ([W.LPCWSTR, W.LPCWSTR, ctypes.POINTER(W.UINT)], W.UINT),
            'MsiDatabaseOpenViewW': ([W.UINT, W.LPCWSTR, ctypes.POINTER(W.UINT)], W.UINT),
            'MsiViewExecute': ([W.UINT, W.UINT], W.UINT),
            'MsiViewFetch': ([W.UINT, ctypes.POINTER(W.UINT)], W.UINT),
            'MsiRecordIsNull': ([W.UINT, W.UINT], W.BOOL),
            'MsiRecordGetInteger': ([W.UINT, W.UINT], ctypes.c_int),
            'MsiRecordGetStringW': ([W.UINT, W.UINT, W.LPWSTR, ctypes.POINTER(W.DWORD)], W.UINT),
            'MsiRecordReadStream': ([W.UINT, W.UINT, ctypes.c_void_p, ctypes.POINTER(W.DWORD)], W.UINT),
            'MsiCloseHandle': ([W.UINT], W.UINT),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self.api, name)
            fn.argtypes, fn.restype = args, result
        self.database = W.UINT()
        self.check(self.api.MsiOpenDatabaseW(str(path.resolve()), None, ctypes.byref(self.database)))

    @staticmethod
    def check(code):
        if code:
            raise OSError(f'Windows Installer reference returned {code}')

    def close(self):
        self.api.MsiCloseHandle(self.database)

    def string(self, record, column):
        length = W.DWORD(0)
        code = self.api.MsiRecordGetStringW(record, column, None, ctypes.byref(length))
        require(code in (0, 234) and length.value <= 1024 * 1024, 'native string bound')
        buffer = ctypes.create_unicode_buffer(length.value + 1)
        length.value += 1
        self.check(self.api.MsiRecordGetStringW(record, column, buffer, ctypes.byref(length)))
        return buffer.value

    def blob(self, record, column):
        digest, total = hashlib.sha256(), 0
        while True:
            buffer = ctypes.create_string_buffer(65536)
            size = W.DWORD(len(buffer))
            self.check(self.api.MsiRecordReadStream(record, column, buffer, ctypes.byref(size)))
            if not size.value:
                break
            total += size.value
            require(total <= 128 * 1024 * 1024, 'native Binary stream bound')
            digest.update(buffer.raw[:size.value])
        return {'sha256': digest.hexdigest(), 'size': total}

    def rows(self, table, columns):
        query = 'SELECT ' + ', '.join('`' + name + '`' for name, _ in columns) + ' FROM `' + table + '`'
        view = W.UINT()
        self.check(self.api.MsiDatabaseOpenViewW(self.database, query, ctypes.byref(view)))
        result = []
        try:
            self.check(self.api.MsiViewExecute(view, 0))
            while True:
                record = W.UINT()
                code = self.api.MsiViewFetch(view, ctypes.byref(record))
                if code == 259:
                    break
                self.check(code)
                try:
                    require(len(result) < 100000, 'native row bound')
                    row = {}
                    for index, (name, kind) in enumerate(columns, 1):
                        if self.api.MsiRecordIsNull(record, index):
                            row[name] = None
                        elif kind == 'i':
                            row[name] = self.api.MsiRecordGetInteger(record, index)
                        elif kind == 'b':
                            row[name] = self.blob(record, index)
                        else:
                            row[name] = self.string(record, index)
                    result.append(row)
                finally:
                    self.api.MsiCloseHandle(record)
        finally:
            self.api.MsiCloseHandle(view)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sample', type=Path)
    parser.add_argument('report', type=Path)
    parser.add_argument('--record', required=True, type=Path)
    args = parser.parse_args()
    require(sys.platform == 'win32', 'Windows native reference only')
    report = json.loads(args.report.read_text(encoding='utf-8-sig'))
    digest = hashlib.file_digest(args.sample.open('rb'), 'sha256').hexdigest()
    root = next(a for a in report['artifacts'] if a['parent'] is None and a.get('digests', {}).get('sha256') == digest)
    fact = root['facts']['windows.msi-actions']
    require(not fact['incomplete'], 'only complete supported declarations qualify')
    native, checks = {}, 0
    reader = Installer(args.sample)
    try:
        present = {r['Name'] for r in reader.rows('_Tables', [('Name', 's')])}
        for table, columns in TABLES.items():
            if table not in present:
                continue
            native[table] = reader.rows(table, columns)
    finally:
        reader.close()
    sequences = {s['table']: s for s in fact['sequences']}
    for table, columns in TABLES.items():
        expected = native.get(table, [])
        if table.endswith('Sequence'):
            require(sequences[table]['present'] == (table in native), f'{table}: presence')
            actual = [e['row'] for e in sequences[table]['rows']]
            checks += 1
        elif table == 'CustomAction':
            actual = [a['row'] for a in fact['custom_actions']]
        elif table == 'LaunchCondition':
            actual = fact['launch_conditions']
        else:
            continue
        keys = [name for name, _ in columns]
        normalized = [{k: row[k] for k in keys} for row in actual]
        sort = lambda rows: sorted(rows, key=lambda r: json.dumps(r, sort_keys=True))
        require(sort(normalized) == sort(expected), f'{table}: original row mismatch')
        checks += 1 + len(expected)
    binaries = {r['Name']: r['Data'] for r in native.get('Binary', [])}
    references = root['facts']['windows.msi-action-targets']['references']
    for action, reference in zip(fact['custom_actions'], references):
        require(action['action'] == reference['action'], 'action/reference correspondence')
        source = action['source']
        if reference['status'] == 'matched-supplied-declaration':
            require(source in binaries and binaries[source] is not None, 'native Binary source exists')
            target = next(a for a in report['artifacts'] if a['path'] == reference['target'])
            require(target['parent'] == root['path'], 'target remains inside supplied container')
            require(target['digests']['sha256'] == reference['target_sha256'] == binaries[source]['sha256'], 'native stream hash')
            require(target['size'] == binaries[source]['size'], 'native stream size')
            checks += 4
        expected = [dict(row, table=table) for table, rows in native.items() if table.endswith('Sequence')
                    for row in rows if row['Action'] == action['action']]
        actual = [dict(row['row'], table=row['table']) for row in action['schedules']]
        require(sorted(expected, key=str) == sorted(actual, key=str), 'action retains every native schedule occurrence')
        checks += 1
    require(fact['conditions_evaluated'] is False and fact['execution_established'] is False, 'static declarations only')
    args.record.parent.mkdir(parents=True, exist_ok=True)
    args.record.write_text(json.dumps({'sample': args.sample.name, 'sha256': digest,
        'reader': 'Windows Installer msi.dll, MsiOpenDatabaseW read-only', 'tables': native,
        'checks': checks, 'execution': 'none', 'installation': 'none'}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'PASS: {checks} native MSI declaration and Binary-stream checks')


if __name__ == '__main__':
    main()
