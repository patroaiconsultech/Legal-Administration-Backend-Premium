import argparse
from .security import hash_password

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hash-password")
    h.add_argument("password")
    args = p.parse_args()
    if args.cmd == "hash-password":
        print(hash_password(args.password))

if __name__ == "__main__":
    main()
