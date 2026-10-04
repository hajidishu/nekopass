#!/usr/bin/env python3
"""Package only the panel binary, built web files and service manager."""
import argparse
import io
import pathlib
import tarfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', type=pathlib.Path, required=True)
p.add_argument('--web', type=pathlib.Path, required=True)
p.add_argument('--manager', type=pathlib.Path, required=True)
p.add_argument('--output', type=pathlib.Path, required=True)
a = p.parse_args()
repo = pathlib.Path(__file__).resolve().parents[1]
assert a.output.resolve().is_relative_to(repo/'dist'), 'Output must stay in dist'
assert (a.web/'pages').is_dir() and (a.web/'assets').is_dir(), 'Build the frontend first'
with a.binary.open('rb') as binary:
    assert binary.read(4)==b'\x7fELF', 'Panel binary must be a Linux executable'
a.output.parent.mkdir(parents=True, exist_ok=True)
with tarfile.open(a.output, 'w:gz') as archive:
    def add(path, name, executable=False):
        assert path.is_file() and not path.is_symlink(), 'Unexpected file/link'
        data = path.read_bytes()
        if name == 'bin/nekopassctl':
            data = data.replace(b'\r\n', b'\n')
        info = tarfile.TarInfo(name)
        info.size, info.mode = len(data), 0o755 if executable else 0o644
        archive.addfile(info, io.BytesIO(data))
    add(a.binary, 'bin/nekopass', True)
    add(a.manager, 'bin/nekopassctl', True)
    if (repo/'LICENSE').is_file():
        add(repo/'LICENSE', 'LICENSE')
    add(repo / 'scripts/nekopass-update.py', 'bin/nekopass-update', True)
    for file in sorted(a.web.rglob('*')):
        if file.is_dir():
            assert not file.is_symlink()
            continue
        assert file.suffix.lower() in {'.html','.js','.css','.svg','.woff','.woff2','.png','.ico'}, 'Unexpected web file'
        add(file, 'web/'+file.relative_to(a.web).as_posix())
print('Panel release ready:', a.output)
