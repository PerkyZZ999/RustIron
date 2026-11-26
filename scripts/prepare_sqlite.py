#!/usr/bin/env python3
"""Verify/build project-local unmodified upstream SQLite; --fetch explicitly permits download."""
from __future__ import annotations
import argparse,hashlib,io,json,pathlib,subprocess,tempfile,tomllib,urllib.request,zipfile
ROOT=pathlib.Path(__file__).resolve().parent.parent
PIN=tomllib.loads((ROOT/'native/sqlite.toml').read_text())
BASE=ROOT/'target/native'
DEST=BASE/('sqlite-'+PIN['version'])
MAX_ARCHIVE=8*1024*1024
ARTIFACTS=['lib/libsqlite3.a','include/sqlite3.h','lib/pkgconfig/sqlite3.pc']

def sha(data):return hashlib.sha256(data).hexdigest()
def verify_archive(data):
    if len(data)>MAX_ARCHIVE or hashlib.sha3_256(data).hexdigest()!=PIN['archive_sha3_256']:
        raise ValueError('SQLite archive checksum/size mismatch')
    archive=zipfile.ZipFile(io.BytesIO(data));prefix=PIN['archive'][:-4]+'/'
    source=archive.read(prefix+'sqlite3.c');header=archive.read(prefix+'sqlite3.h')
    if hashlib.sha3_256(source).hexdigest()!=PIN['source_sha3_256']:
        raise ValueError('SQLite amalgamation checksum mismatch')
    return source,header

def check_cache(dest=DEST):
    receipt=json.loads((dest/'receipt.json').read_text())
    if receipt['pin_sha256']!=sha((ROOT/'native/sqlite.toml').read_bytes()):raise ValueError('SQLite pin changed; explicit fresh native build required')
    if set(receipt['artifacts'])!=set(ARTIFACTS):raise ValueError('Unexpected native artifacts')
    for name,checksum in receipt['artifacts'].items():
        if sha((dest/name).read_bytes())!=checksum:raise ValueError('SQLite native artifact checksum mismatch')
    return receipt

def prepare(fetch, dest=DEST):
    if dest.exists():return check_cache(dest)
    cache=ROOT/'target/native-download'/PIN['archive']
    if not cache.exists():
        if not fetch:raise ValueError('Native SQLite missing; run python3 scripts/prepare_sqlite.py --fetch')
        data=urllib.request.urlopen(PIN['url'],timeout=30).read(MAX_ARCHIVE+1)
        verify_archive(data);cache.parent.mkdir(parents=True,exist_ok=True);cache.write_bytes(data)
    source,header=verify_archive(cache.read_bytes());dest.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sqlite-build-',dir=dest.parent) as temp:
        work=pathlib.Path(temp);(work/'include').mkdir();(work/'lib/pkgconfig').mkdir(parents=True)
        (work/'sqlite3.c').write_bytes(source);(work/'include/sqlite3.h').write_bytes(header)
        subprocess.run(['/usr/bin/cc',*PIN['cflags'],'-c',str(work/'sqlite3.c'),'-o',str(work/'sqlite3.o')],check=True)
        subprocess.run(['/usr/bin/ar','rcs',str(work/'lib/libsqlite3.a'),str(work/'sqlite3.o')],check=True)
        (work/'lib/pkgconfig/sqlite3.pc').write_text('prefix=${pcfiledir}/../..\nlibdir=${prefix}/lib\nincludedir=${prefix}/include\nName: SQLite\nDescription: Rustiron pinned unmodified SQLite\nVersion: '+PIN['version']+'\nLibs: -L${libdir} -lsqlite3\nLibs.private: -lm -ldl -lpthread\nCflags: -I${includedir}\n')
        receipt=dict(version=PIN['version'],source_id=PIN['source_id'],pin_sha256=sha((ROOT/'native/sqlite.toml').read_bytes()),archive_sha3_256=PIN['archive_sha3_256'],source_sha3_256=PIN['source_sha3_256'],compiler=subprocess.check_output(['/usr/bin/cc','--version'],text=True).splitlines()[0],cflags=PIN['cflags'],artifacts={name:sha((work/name).read_bytes()) for name in ['lib/libsqlite3.a','include/sqlite3.h','lib/pkgconfig/sqlite3.pc']})
        (work/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        # Publish only verified source, header, static library and build receipt.
        (work/'sqlite3.o').unlink();(work/'sqlite3.c').unlink()
        work.rename(dest)
    return check_cache(dest)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--fetch',action='store_true');args=parser.parse_args()
    print(json.dumps(prepare(args.fetch),indent=2))

if __name__=='__main__':main()
