"""Download the NSL-KDD benchmark files into data/nsl-kdd.

NSL-KDD: Tavallaee, Bagheri, Lu, Ghorbani, "A Detailed Analysis of the KDD CUP 99
Data Set", IEEE CISDA 2009 (Canadian Institute for Cybersecurity, UNB).
The files are fetched from a public GitHub mirror.
"""

import os
import urllib.request

BASE_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/"
FILES = ["KDDTrain+.txt", "KDDTest+.txt"]
OUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "nsl-kdd"
)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    for name in FILES:
        dest = os.path.join(OUT_DIR, name)
        if os.path.exists(dest):
            print(f"[=] {name} already present")
            continue
        print(f"[+] Downloading {name} ...")
        urllib.request.urlretrieve(BASE_URL + name, dest)
    print(f"[+] Done. Files are in {OUT_DIR}")


if __name__ == "__main__":
    main()
