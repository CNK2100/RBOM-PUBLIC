#!/usr/bin/env python

import os
import toml
from pathlib import Path


def main():
    # Find the target gen path.
    dst_dir = Path(__file__).parent / ".." / "gen"
    if not dst_dir.exists():
        raise RuntimeError("no gen directory found")
    
    # Read 111 and 112 CS configuration files from our directory.
    src_dir = Path(__file__).parent / "configs"
    for conf_file in src_dir.glob("cs*.toml"):
        # Find equivalent in gen/
        p = Path(conf_file).name
        dsts = list(dst_dir.glob("AS*/" + p))
        if len(dsts) != 1:
            raise RuntimeError(f"{p} found != once in gen/ : {dsts}")
        dst_conf_file = dsts[0].resolve()

        # Read extra configuration and write it to destination.
        with open(dst_conf_file, "r") as f:
            dst_conf = toml.load(f)
            if "drkey" in dst_conf:
                print(f"file {dst_conf_file} already patched. Replacing.")
            with open(conf_file, "r") as f:
                # Extract the drkey.qkd_config configuration.
                dst_conf["drkey"] = toml.load(f)["drkey"]
        with open(dst_conf_file, "w") as f:
            toml.dump(dst_conf, f)
    # Read 111 and 112 SD configuration files from our directory.
    for conf_file in src_dir.glob("sd*.toml"):
        # Find equivalent in gen/
        as_num = Path(conf_file).stem[-3:]
        dsts = list(dst_dir.glob(f"AS*{as_num}/sd.toml"))
        if len(dsts) != 1:
            raise RuntimeError(f"{conf_file} found != once in gen/ : {dsts}")
        dst_conf_file = dsts[0].resolve()
        
        # Read extra configuration and write it to destination.
        with open(dst_conf_file, "r") as f:
            dst_conf = toml.load(f)
            if "drkey_level2_db" in dst_conf:
                print(f"file {dst_conf_file} already patched. Replacing.")
            with open(conf_file, "r") as f:
                # Extract the drkey.qkd_config configuration.
                dst_conf["drkey_level2_db"] = toml.load(f)["drkey_level2_db"]
        with open(dst_conf_file, "w") as f:
            toml.dump(dst_conf, f)

    # Lastly, remove the PQC from AS ff00:0:200
    paths = [
        "PQ_cp-as.key",
        "PQ_cp-as.tmpl",
        "ISD1-ASff00_0_200_PQ.pem",
    ]
    dirpath = Path(__file__).parent / ".." / "gen" / "ASff00_0_200" / "crypto" / "as"
    for p in paths:
        os.remove(dirpath / p)

if __name__ == "__main__":
    main()
