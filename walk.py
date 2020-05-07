from pprint import pprint
import re
import io
import os
import asyncio
from aiohttp import ClientSession
from aiofile import AIOFile
import sys
import json
from libarchive.public import memory_reader as archive_reader
import tempfile
import itertools
import logging
import coloredlogs

coloredlogs.install()

logging.basicConfig(level=logging.DEBUG)

PAT = re.compile(r"\(WARNING: No symbols, (.+\.pdb), ([0-9A-F]+)\)")
SYMCACHE = "/home/calixte/symcache"
SYM_SRV = "SRV*~/symcache*https://msdl.microsoft.com/download/symbols;SRV*~/symcache*https://symbols.mozilla.org"
OLD = "old_sym"
NEW = "new_sym"
BINARIES = "binaries"
EXTRA_BINARIES = "extra_binaries"
MINIDUMPS = "minidumps"
DUMP_SYMS = "/home/calixte/dev/mozilla/dump_syms.calixteman/target/release/dump_syms"
SERVERS = ["https://symbols.mozilla.org", "https://msdl.microsoft.com/download/symbols"]
HEADERS = {"User-Agent": "cdenizet@mozilla.com"}


def get_socorro_token():
    with open(".socorro", "r") as In:
        token = In.read()
    token = token.strip()
    return str(token)


SOCORRO_TOKEN = get_socorro_token()


def get_headers(base):
    base.update(HEADERS)
    return base


async def exists(client, url):
    logging.info(f"Check data from {url}")
    async with client.head(url, headers=HEADERS) as resp:
        return resp.status != 404


async def fetch(client, url):
    logging.info(f"Fetch data from {url}")
    async with client.get(url, headers=HEADERS) as resp:
        return await resp.read()


async def write(data, path):
    logging.info(f"Write data to {path}")
    parent = os.path.dirname(path)
    if not os.path.exists(parent):
        os.makedirs(parent)

    async with AIOFile(path, "wb") as Out:
        await Out.write(data)


def get_code_id(data, url):
    line = data.split(b"\n", 2)[1]
    if line.startswith(b"INFO CODE_ID"):
        toks = line.split(b" ")
        return {"code_id": toks[2].strip().decode(), "name": toks[3].strip().decode()}
    else:
        logging.warning(f"No CODE_ID for {url}")


async def collect_data(client, pdb, debug_id, cache_sym):
    exts = ["sym", "pdb", "pd_"]
    stem = os.path.splitext(pdb)[0]
    binaries = []
    missing = []
    for e in exts:
        f = f"{stem}.{e}"
        cache = cache_sym if e == "sym" else SYMCACHE
        cache = os.path.join(cache, f"{pdb}/{debug_id}/{f}")
        if os.path.exists(cache):
            continue

        for base in SERVERS:
            url = f"{base}/{pdb}/{debug_id}/{f}"
            if await exists(client, url):
                data = await fetch(client, url)
                if e == "sym":
                    code_id = get_code_id(data, url)
                    if code_id:
                        binaries.append(code_id)
                    else:
                        missing.append(f"{SYMCACHE}/{pdb}/{debug_id}/{stem}.pdb")

                await write(data, cache)
                break

    return binaries, missing


async def collect_missing_binary(client, binary, cache):
    name = binary["name"]
    code_id = binary["code_id"]
    stem, ext = os.path.splitext(name)
    exts = [ext, ext[:-1] + "_"]

    for e in exts:
        path = os.path.join(cache, name)
        if os.path.exists(path):
            continue

        f = f"{stem}{e}"
        for base in SERVERS:
            url = f"{base}/{name}/{code_id}/{f}"
            if await exists(client, url):
                data = await fetch(client, url)
                await write(data, path)
                break


async def collect_missing_binaries(client, binaries, cache):
    tasks = []
    for binary in binaries:
        tasks.append(collect_missing_binary(client, binary, cache))
    await asyncio.gather(*tasks)


async def get_minidump(client, crash_id, cache):
    async with client.get(
        "https://crash-stats.mozilla.com/api/RawCrash/",
        params={"crash_id": crash_id, "format": "raw"},
        headers=get_headers({"Auth-Token": SOCORRO_TOKEN}),
    ) as resp:
        data = await resp.read()
        path = os.path.join(cache, f"{crash_id}.dmp")
        await write(data, path)

        return path


async def get_metadata(client, crash_id):
    async with client.get(
        "https://crash-stats.mozilla.com/api/UnredactedCrash/",
        params={"crash_id": crash_id, "datatype": "unredacted"},
        headers=get_headers({"Auth-Token": SOCORRO_TOKEN}),
    ) as resp:
        data = await resp.json()
        print(data)
        buildid = data["build"]
        channel = data["release_channel"]
        is_64 = "64" in data["cpu_arch"]
        is_arm = "arm" in data["cpu_arch"]
        platform = "win64" if is_64 else "win32"
        if is_64:
            target = "aarch64" if is_arm else "x86_64"
        else:
            target = "arm" if is_arm else "x86"

        return {
            "buildid": buildid,
            "channel": channel,
            "platform": platform,
            "target": target,
        }


async def get_binary_url(client, meta):
    params = {
        "size": 256,
        "query": {
            "bool": {
                "must": [
                    {"term": {"build.id": meta["buildid"]}},
                    {"term": {"target.channel": meta["channel"]}},
                    {"term": {"target.locale": "en-US"}},
                    {"term": {"source.product": "firefox"}},
                    {"term": {"target.platform": meta["platform"]}},
                ]
            }
        },
    }
    params = json.dumps(params)
    async with client.post(
        "https://buildhub.moz.tools/api/search", data=params
    ) as resp:
        data = await resp.json()
        if meta["target"] == "x86":
            alt = "i686"
        else:
            alt = meta["target"]

        for hit in data["hits"]["hits"]:
            source = hit["_source"]
            build = source["build"]
            if not (build["target"].startswith(meta["target"]) or build["target"].startswith(alt)) and len(data["hits"]["hits"]) > 1:
                continue
            url = source["download"]["url"]
            return url


async def uncompress(data, cache):
    f = tempfile.NamedTemporaryFile()
    f.write(data)

    proc = await asyncio.create_subprocess_shell(
        f"7zr e {f.name} -y -ir!*.dll -ir!*.exe -o{cache}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate()
    f.close()


async def get_binary(client, crash_id, cache):
    meta = await get_metadata(client, crash_id)

    path = os.path.join(cache, meta["buildid"], meta["platform"])
    if os.path.exists(path):
        return path
    os.makedirs(path)

    url = await get_binary_url(client, meta)
    assert url is not None, "Empty URL !!"
    
    logging.info(f"Get binary from {url}")
    async with client.get(url) as resp:
        assert resp.status == 200
        binary = await resp.read()
        await uncompress(binary, path)

    return path


async def run_helper(cmd):
    logging.info(f"Run command {cmd}")
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    out, err = await proc.communicate()
    err = err.decode().strip()
    if err:
        logging.error(f"\nError with {cmd}")
        logging.error(err)


async def run_dump_syms(dll_path, extra_path, missing, sym_cache):
    tasks = []
    binaries = set(itertools.chain(os.listdir(dll_path), os.listdir(extra_path)))
    for f in binaries:
        extra = os.path.join(extra_path, f)
        if os.path.exists(extra):
            path = extra
        else:
            path = os.path.join(dll_path, f)
        tasks.append(
            run_helper(
                f"{DUMP_SYMS} {path} --store {sym_cache} --symbol-server '{SYM_SRV}'"
            )
        )

    for f in missing:
        tasks.append(
            run_helper(
                f"{DUMP_SYMS} {f} --store {sym_cache}"
            )
        )
    await asyncio.gather(*tasks)


async def get_missing_syms(client, path, cache_sym):
    proc = await asyncio.create_subprocess_shell(
        f"./breakpad/bin/minidump_stackwalk {path}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, _ = await proc.communicate()
    out = out.decode()
    tasks = []
    for m in PAT.finditer(out):
        pdb = m.group(1)
        debug_id = m.group(2)
        task = collect_data(client, pdb, debug_id, cache_sym)
        tasks.append(task)

    res = await asyncio.gather(*tasks)
    binaries = [b for (b, _) in res]
    missing = [m for (_, m) in res]
    binaries = itertools.chain.from_iterable(binaries)
    missing = itertools.chain.from_iterable(missing)

    return binaries, missing


async def get_stack(dmp_path, old_path, new_path):
    new_proc = asyncio.create_subprocess_shell(
        f"./breakpad/bin/minidump_stackwalk -m {dmp_path} {new_path}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    old_proc = asyncio.create_subprocess_shell(
        f"./breakpad/bin/minidump_stackwalk -m {dmp_path} {old_path}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    new_proc, old_proc = await asyncio.gather(new_proc, old_proc)

    res = await asyncio.gather(new_proc.communicate(), old_proc.communicate())
    new = res[0][0].decode()
    old = res[1][0].decode()

    return old, new


async def collect(client, crash_id):
    tasks = []
    tasks.append(get_minidump(client, crash_id, MINIDUMPS))
    tasks.append(get_binary(client, crash_id, os.path.join(crash_id, BINARIES)))

    dmp_path, bin_path = await asyncio.gather(*tasks)
    binaries, missing = await get_missing_syms(client, dmp_path, os.path.join(crash_id, OLD))

    await collect_missing_binaries(client, binaries, os.path.join(crash_id, EXTRA_BINARIES))
    await run_dump_syms(bin_path, os.path.join(crash_id, EXTRA_BINARIES), missing, os.path.join(crash_id, NEW))

    return await get_stack(dmp_path, os.path.join(crash_id, OLD), os.path.join(crash_id, NEW))


def parse(data):
    res = {}
    res["modules"] = modules = {}
    res["threads"] = threads = {}
    for line in data.split("\n"):
        line = line.strip()
        if not line:
            continue
        toks = line.split("|")
        if toks[0] == "OS":
            res["os"] = toks[1:]
        elif toks[0] == "CPU":
            res["cpu"] = toks[1:]
        elif toks[0] == "GPU":
            res["gpu"] = toks[1:]
        elif toks[0] == "Crash":
            res["crash"] = toks[1:]
        elif toks[0] == "Module":
            modules[toks[1]] = toks[2:]
        elif toks[0].isdigit():
            n = int(toks[0])
            if n in threads:
                frames = threads[n]
            else:
                threads[n] = frames = []
            frame = int(toks[1])
            assert frame == len(frames)
            frames.append(
                {
                    "dll": toks[2],
                    "fun": toks[3],
                    "file": toks[4],
                    "line": int(toks[5]) if toks[5].isdigit() else "null",
                    "addr": toks[6],
                }
            )
    return res


def trunc_name(s, n):
    return s[:(n - 3)] + "..." if len(s) > n else s


def side_by_side(old, new):
    size = 50
    cols = f"{{: >5}} {{: >{size}}} {{: >{size}}}\n"
    s =  cols.format("", "Old", "New")
    s +=  cols.format("", "---", "---")
    for t in ["dll", "line", "addr"]:
        s += cols.format(t + ":", old[t], new[t])
    o_fun = trunc_name(old["fun"], size) 
    n_fun = trunc_name(new["fun"], size)
    s += cols.format("fun:", o_fun, n_fun)
    
    return s


def compare(old, new, crash_id):
    old = parse(old)
    new = parse(new)
    with open(os.path.join(crash_id, "old.json"), "w") as Out:
        json.dump(old, Out, sort_keys=True, indent=4, separators=(',', ': '))
    with open(os.path.join(crash_id, "new.json"), "w") as Out:
        json.dump(new, Out, sort_keys=True, indent=4, separators=(',', ': '))
    
    assert old["os"] == new["os"]
    assert old["cpu"] == new["cpu"]
    assert old["gpu"] == new["gpu"]
    assert old["crash"] == new["crash"]
    assert old["modules"] == new["modules"]
    assert len(old["threads"]) == len(new["threads"])

    for ((o_n, o_frames), (n_n, n_frames)) in zip(
        sorted(old["threads"].items(), key=lambda p: p[0]),
        sorted(new["threads"].items(), key=lambda p: p[0]),
    ):
        assert o_n == n_n

        if len(o_frames) != len(n_frames):
            logging.critical(f"In `Thread {o_n}': not the same frames number")
        for (n, (o_frame, n_frame)) in enumerate(zip(o_frames, n_frames)):
            if not n_frame["fun"].startswith("thread_start<unsigned int ("):
                if o_frame["dll"] != n_frame["dll"] or o_frame["line"] != n_frame["line"] or o_frame["addr"] != n_frame["addr"]:
                    logging.critical("Not the same frame ({}) in Thread {}:\n{}".format(n + 1, o_n, side_by_side(o_frame, n_frame)))
            

async def foo(crash_id):
    loop = asyncio.get_event_loop()
    async with ClientSession(loop=loop) as client:
        old, new = await collect(client, crash_id)
        compare(old, new, crash_id)
        logging.info("Finished !")


asyncio.run(foo("4bd770c5-2bcf-4d6a-bf50-f90cd0200506"))

