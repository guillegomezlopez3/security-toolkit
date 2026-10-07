"""Command line interface.

python -m seckit.cli check 'MyPassw0rd!'
python -m seckit.cli generate --length 20
python -m seckit.cli hash 'secret'
python -m seckit.cli verify 'secret' '<stored hash>'
python -m seckit.cli checksum file.bin
"""
import argparse
import sys

from . import hashing, password


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="seckit", description="Small security toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check"); c.add_argument("password")
    g = sub.add_parser("generate"); g.add_argument("--length", type=int, default=16); g.add_argument("--no-symbols", action="store_true")
    h = sub.add_parser("hash"); h.add_argument("password")
    v = sub.add_parser("verify"); v.add_argument("password"); v.add_argument("stored")
    f = sub.add_parser("checksum"); f.add_argument("path"); f.add_argument("--algo", default="sha256")
    a = p.parse_args(argv)

    if a.cmd == "check":
        r = password.assess(a.password)
        print(f"{r['label']} (score {r['score']}/4, ~{r['entropy_bits']} bits)")
        for issue in r["issues"]:
            print(f"  - {issue}")
    elif a.cmd == "generate":
        print(password.generate(a.length, symbols=not a.no_symbols))
    elif a.cmd == "hash":
        print(hashing.hash_password(a.password))
    elif a.cmd == "verify":
        ok = hashing.verify_password(a.password, a.stored)
        print("match" if ok else "no match")
        return 0 if ok else 1
    elif a.cmd == "checksum":
        print(f"{hashing.file_checksum(a.path, a.algo)}  {a.path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
