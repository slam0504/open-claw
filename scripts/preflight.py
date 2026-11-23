"""Read-only inventory for exact Phase 1 artifact pins, not a release gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time

SCHEMA = "openclaw-preflight-pins-v1"
DIGEST_KEYS = {"python_sha256", "node_sha256", "docker_cli_sha256",
               "runner_sha256", "template_sha256", "model_sha256"}
PIN_KEYS = DIGEST_KEYS | {"schema", "model_bytes", "image_id"}
PORTS = (18960, 19234, 19235)
ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C", "TZ": "UTC"}
READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class Refused(Exception):
    pass


def need(condition, reason="identity_unconfirmed"):
    if not condition:
        raise Refused(reason)


def report(status, reason, checks):
    obj = {"schema": "openclaw-preflight-v1", "status": status,
           "reason": reason, "checks": checks, "workload_started": False,
           "release_authorized": False, "security_qualified": False}
    print(json.dumps(obj, separators=(",", ":"), sort_keys=True))


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        report("incomplete", "invalid_arguments", {})
        raise SystemExit(2)


def path(value):
    need(type(value) is str and 1 < len(value) <= 1024 and value.startswith("/")
         and not value.startswith("//") and not any(c in value for c in "\0\r\n")
         and os.path.normpath(value) == value, "path_unconfirmed")
    return Path(value)


def sig(s):
    return s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def regular(p, *, digest=None, size=None, header=None, limit=256 * 1024**2,
            executable=False, owner_only=False, payload=False):
    need(p.resolve(strict=True) == p, "path_unconfirmed")
    fd = os.open(p, READ)
    try:
        a = os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and sig(a) == sig(p.lstat()))
        need(0 < a.st_size <= limit and (size is None or a.st_size == size), "size_unconfirmed")
        if owner_only:
            need(a.st_uid == os.getuid() and stat.S_IMODE(a.st_mode) == 0o600, "config_unconfirmed")
        if executable:
            need(a.st_uid in (0, os.getuid()) and not a.st_mode & 0o022 and a.st_mode & 0o111)
        with os.fdopen(os.dup(fd), "rb") as f:
            if header is not None:
                need(f.read(len(header)) == header, "header_mismatch")
            data = None
            if digest is not None:
                f.seek(0)
                if payload:
                    data = f.read(limit + 1)
                    need(len(data) == a.st_size and hashlib.sha256(data).hexdigest() == digest, "digest_mismatch")
                else:
                    need(hashlib.file_digest(f, "sha256").hexdigest() == digest, "digest_mismatch")
        need(sig(a) == sig(os.fstat(fd)) == sig(p.lstat()) and p.resolve(strict=True) == p)
        return data if payload else sig(a)
    finally:
        os.close(fd)


def hex_digest(x):
    return type(x) is str and re.fullmatch(r"[0-9a-f]{64}", x) is not None and x != "0" * 64


def read_pins(filename, expected, python_expected):
    def unique(pairs):
        output = {}
        for k, v in pairs:
            need(k not in output, "pins_unconfirmed")
            output[k] = v
        return output

    need(hex_digest(expected) and hex_digest(python_expected), "pins_unconfirmed")
    raw = regular(path(filename), digest=expected, limit=8192, payload=True)
    obj = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique)
    need(type(obj) is dict and set(obj) == PIN_KEYS and obj["schema"] == SCHEMA
         and all(hex_digest(obj[k]) for k in DIGEST_KEYS)
         and obj["python_sha256"] == python_expected
         and type(obj["model_bytes"]) is int and 8 <= obj["model_bytes"] <= 128 * 1024**3
         and type(obj["image_id"]) is str and obj["image_id"].startswith("sha256:")
         and hex_digest(obj["image_id"][7:]), "pins_unconfirmed")
    return obj


def capture(argv, *, executable=None, seconds=3, ceiling=4096):
    # Trusted fixed commands only. Bound both streams; never expose their contents.
    end = time.monotonic() + seconds
    p = subprocess.Popen(argv, executable=executable, env=ENV,
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, close_fds=True, bufsize=0)
    streams = p.stdout, p.stderr
    bufs = bytearray(), bytearray()
    try:
        with selectors.DefaultSelector() as sel:
            for i, f in enumerate(streams):
                os.set_blocking(f.fileno(), False)
                sel.register(f, selectors.EVENT_READ, i)
            while sel.get_map():
                left = end - time.monotonic()
                need(left > 0, "probe_timeout")
                ready = sel.select(left)
                need(bool(ready), "probe_timeout")
                for key, _ in ready:
                    try:
                        chunk = os.read(key.fd, ceiling + 1 - sum(map(len, bufs)))
                    except BlockingIOError:
                        continue
                    if chunk:
                        bufs[key.data].extend(chunk)
                        need(sum(map(len, bufs)) <= ceiling, "probe_output_unconfirmed")
                    else:
                        sel.unregister(key.fileobj)
        left = end - time.monotonic()
        need(left > 0, "probe_timeout")
        code = p.wait(timeout=left)
        need(time.monotonic() < end, "probe_timeout")
        return code, bytes(bufs[0]), bytes(bufs[1])
    except subprocess.TimeoutExpired:
        raise Refused("probe_timeout") from None
    finally:
        try:
            if p.poll() is None:
                p.kill()  # Only the read-only client spawned above; never a service.
                p.wait(timeout=0.5)
        finally:
            try:
                streams[0].close()
            finally:
                streams[1].close()


def node_at(value, digest):
    p = path(value)
    a = regular(p, digest=digest, executable=True)
    need(capture((str(p), "--version")) == (0, b"v26.13.1\n", b""), "version_unconfirmed")
    need(sig(p.lstat()) == a)


def config_dir(value):
    p = path(value)
    need(p.resolve(strict=True) == p, "config_unconfirmed")
    a = p.lstat()
    need(stat.S_ISDIR(a.st_mode) and a.st_uid == os.getuid()
         and stat.S_IMODE(a.st_mode) == 0o700 and set(os.listdir(p)) == {"config.json"}, "config_unconfirmed")
    raw = b'{"auths":{}}\n'
    regular(p / "config.json", digest=hashlib.sha256(raw).hexdigest(), size=len(raw),
            limit=64, owner_only=True)
    need(sig(p.lstat()) == sig(a), "config_unconfirmed")
    return p, sig(a)


def socket_at(value):
    s = path(value)
    a = s.lstat()
    need(s.resolve(strict=True) == s and stat.S_ISSOCK(a.st_mode)
         and a.st_uid == os.getuid() and os.getuid() == os.geteuid(), "socket_unconfirmed")
    return s, sig(a)


def cli_at(value, digest):
    alias = path(value)
    a = alias.lstat()
    need(alias.name == "docker" and stat.S_ISLNK(a.st_mode)
         and alias.parent.resolve(strict=True) == alias.parent, "cli_alias_unconfirmed")
    binary = alias.resolve(strict=True)
    need(binary.name == "docker-tools", "cli_alias_unconfirmed")
    pin = regular(binary, digest=digest, executable=True)
    need(sig(alias.lstat()) == sig(a) and alias.resolve(strict=True) == binary)
    return alias, sig(a), binary, pin


def engine_check(cli, sock, cfg, pins):
    # No default context/daemon, discovery, image list, pull, or remote endpoint.
    alias, a, binary, b = cli_at(cli, pins['docker_cli_sha256'])
    image = pins['image_id']
    s, c = socket_at(sock)
    d, x = config_dir(cfg)
    argv = (str(alias), "--config", str(d), "--host", "unix://" + str(s),
            "image", "inspect", "--format", "{{.Id}} {{.Os}} {{.Architecture}}", image)
    result = capture(argv, executable=str(binary))
    need(sig(alias.lstat()) == a and alias.resolve(strict=True) == binary
         and sig(binary.lstat()) == b and socket_at(sock) == (s, c) and config_dir(cfg) == (d, x),
         "identity_unconfirmed")
    need(result == (0, (image + " linux arm64\n").encode(), b""), "pinned_image_unconfirmed")


def check_ports():
    for port in PORTS:
        code, out, err = capture(("/usr/sbin/lsof", "-nP", "-iTCP:" + str(port),
                                  "-sTCP:LISTEN", "-Fpn"))
        if (code, out, err) == (1, b"", b""):
            continue
        need(not (code == 0 and out and not err), "listener_observed")
        raise Refused("listener_visibility_unconfirmed")


def assess(args):
    checks = {"platform": "macos_arm64"}
    blocked = False
    incomplete = False

    def item(name, required, work, good="pass", partial=False):
        nonlocal blocked, incomplete
        if not required:
            checks[name] = "path_required"
            incomplete = True
            return
        try:
            work()
            checks[name] = good
            incomplete |= partial
        except FileNotFoundError:
            checks[name] = "not_found"
            incomplete = True
        except Refused as exc:
            checks[name] = exc.args[0]
            blocked = True
        except (OSError, subprocess.SubprocessError, ValueError, RuntimeError):
            checks[name] = "read_unconfirmed"
            blocked = True

    item("python", True,
         lambda: (need(sys.version_info[:3] == (3, 13, 18), "version_unconfirmed"),
                  need(hex_digest(args.python_sha256) and str(path(sys.executable)) == args.python, "identity_unconfirmed"),
                  regular(path(sys.executable), digest=args.python_sha256, limit=10485760, executable=True)))
    if checks["python"] != "pass":
        return "blocked", "python_identity_unconfirmed", checks, 1
    pins = None
    if args.pins and args.pins_sha256:
        try:
            pins = read_pins(args.pins, args.pins_sha256, args.python_sha256)
            checks["artifact_pins"] = "pass"
        except (Refused, OSError, ValueError, RuntimeError):
            return "blocked", "artifact_pins_unconfirmed", {**checks, "artifact_pins": "unconfirmed"}, 1
    else:
        checks["artifact_pins"] = "paths_and_independent_pins_required"
        incomplete = True
    if pins is not None:
        item("node", args.node, lambda: node_at(args.node, pins["node_sha256"]))
        item("runner", args.runner,
             lambda: regular(path(args.runner), digest=pins["runner_sha256"], executable=True))
        item("template", args.template,
             lambda: regular(path(args.template), digest=pins["template_sha256"], limit=262144))
        item("model", args.model,
             lambda: regular(path(args.model), size=pins["model_bytes"], limit=pins["model_bytes"],
                             header=b"GGUF\x03\0\0\0",
                             digest=pins["model_sha256"] if args.full_model_hash else None),
             good="pass" if args.full_model_hash else "header_size_only", partial=not args.full_model_hash)
        if args.docker_socket and args.docker_config:
            item("docker_image", args.docker_cli,
                 lambda: engine_check(args.docker_cli, args.docker_socket, args.docker_config, pins))
        else:
            checks["docker_image"] = "explicit_socket_and_config_required"
            incomplete = True
    item("fixed_listeners", True, check_ports, good="none_observed")
    if blocked:
        return "blocked", "one_or_more_checks_unconfirmed", checks, 1
    if incomplete:
        return "incomplete", "one_or_more_checks_not_completed", checks, 2
    return "checks_passed", "read_only_inventory", checks, 0


def main():
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        report("blocked", "unsupported_platform", {"platform": "unsupported"})
        return 1
    parser = Parser(add_help=False, allow_abbrev=False)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--python")
    parser.add_argument("--python-sha256")
    parser.add_argument("--pins")
    parser.add_argument("--pins-sha256")
    parser.add_argument("--node")
    parser.add_argument("--docker-cli")
    parser.add_argument("--docker-socket")
    parser.add_argument("--docker-config")
    parser.add_argument("--runner")
    parser.add_argument("--model")
    parser.add_argument("--template")
    parser.add_argument("--full-model-hash", action="store_true")
    args = parser.parse_args()
    if bool(args.pins) != bool(args.pins_sha256) or bool(args.python) != bool(args.python_sha256):
        parser.error("incomplete pair")
    status, reason, checks, code = assess(args)
    report(status, reason, checks)
    return code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        report("blocked", "interrupted", {})
        raise SystemExit(1)
