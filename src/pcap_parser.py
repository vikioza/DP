import os
import glob
import pyshark
import time

import pandas as pd
from datetime import datetime, timezone
from multiprocessing import Pool
from functools import partial

from sniffer.packet import PacketInfo


CSV_DIR = "C:\VScode_Projects\DP\datasets\CIC-IDS-2017\\raw\csv"
PCAP_DIR = "C:\VScode_Projects\DP\datasets\CIC-IDS-2017\\raw\pcap"
COLS = [
    "Flow ID",
    " Source IP",
    " Source Port",
    " Destination IP",
    " Destination Port",
    " Protocol",
    " Timestamp",
    " Flow Duration",
    " Label",
]


def read_csv(dir: str):
    print("READING CSV FILES...")

    extension = "*.csv"
    files = glob.glob(f"{dir}/{extension}")

    dfs = []
    for file in files:
        print(f"READING {file}")
        if "Thursday-WorkingHours-Morning" in file:
            dfs.append(
                pd.read_csv(file, usecols=COLS, encoding="cp1252", low_memory=False)
            )
        else:
            dfs.append(pd.read_csv(file, usecols=COLS))

    print("MERGING CSV FILES...")
    df = pd.concat(dfs, ignore_index=True)
    df.columns = df.columns.str.strip()

    print('DROPPING ROWS WITH MISSING "Flow ID"...')
    df = df.drop(df[pd.isnull(df["Flow ID"])].index)

    print("FINDING MIN TIMESTAMP...")
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="mixed", dayfirst=True)
    min_timestamp = df["Timestamp"].min()

    return df, min_timestamp


def parse_pcap(file, ts, start_time: float):
    file_name = os.path.basename(file)
    packet_count = 0
    wrong_protocol = 0
    error_count = 0
    capture_start_time = (
        datetime.fromisoformat(str(ts)).replace(tzinfo=timezone.utc).timestamp()
    )

    with open(
        f"C:\VScode_Projects\DP\datasets\CIC-IDS-2017\clean\parsed{file_name}.csv", "w"
    ) as f:
        column_names = [f"payload_byte_{x}" for x in range(1, 1501)] + [
            "ttl",
            "total_len",
            "protocol",
            "t_delta",
            "src_ip",
            "src_p",
            "dst_ip",
            "dst_p",
            "protocol",
            "timestamp",
        ]
        columns_line = ",".join(column_names) + "\n"
        f.write(columns_line)

        print(f"PARSING: {file}")
        capture = pyshark.FileCapture(
            file, keep_packets=False, use_ek=True, include_raw=True
        )
        out = []
        for packet in capture:
            try:
                info = PacketInfo(packet=packet, start_time=capture_start_time)
                if info.has_payload:
                    out_list = [str(x) for x in info.features] + [
                        str(info.number_prot_id["src_ip"]),
                        str(info.number_prot_id["src_p"]),
                        str(info.number_prot_id["dst_ip"]),
                        str(info.number_prot_id["dst_p"]),
                        str(info.number_prot_id["protocol"]),
                        str(info.number_prot_id["timestamp"]),
                    ]
                    out_str = ",".join(out_list) + "\n"
                    out.append(out_str)

                    packet_count += 1
                    if packet_count % 1_000_000 == 0:
                        print(f"COUNT {file_name}: {packet_count}")

                        f.writelines(out)
                        out = []

                        current_time = time.time()
                        print(
                            f"RUNTIME {file_name}: {current_time-start_time:.2f} (seconds)"
                        )

                else:
                    wrong_protocol += 1
                    if wrong_protocol % 1_000_000 == 0:
                        print(f"SKIPPED COUNT {file_name}: {wrong_protocol}")
                        current_time = time.time()
                        print(
                            f"RUNTIME {file_name}: {current_time-start_time:.2f} (seconds)"
                        )

            except TypeError as te:
                print(f"TypeError: {te}")
                error_count += 1
                if error_count % 1_000_000 == 0:
                    print(f"ERROR COUNT {file_name}: {error_count}")
                    current_time = time.time()
                    print(
                        f"RUNTIME {file_name}: {current_time-start_time:.2f} (seconds)"
                    )
                continue

            except AttributeError as te:
                print(f"AttributeError: {te}")
                error_count += 1
                if error_count % 1_000_000 == 0:
                    print(f"ERROR COUNT {file_name}: {error_count}")
                    current_time = time.time()
                    print(
                        f"RUNTIME {file_name}: {current_time-start_time:.2f} (seconds)"
                    )
                continue

        return packet_count, wrong_protocol, error_count


if __name__ == "__main__":
    start_time = time.time()
    df, ts = read_csv(CSV_DIR)

    # Create a bound function with fixed arguments
    bound_parse_pcap = partial(parse_pcap, ts=ts, start_time=start_time)

    files = glob.glob(f"{PCAP_DIR}/*.pcap")
    print(files)
    # Number of parallel processes (adjust based on CPU cores)
    num_processes = 5
    # Process files in parallel
    with Pool(num_processes) as pool:
        results = pool.map(bound_parse_pcap, files)

    # Aggregate results (optional)
    total_packets = sum(r[0] for r in results)
    total_skipped = sum(r[1] for r in results)
    total_errors = sum(r[2] for r in results)

    print(f"Total packets processed: {total_packets}")
    print(f"Total skipped packets: {total_skipped}")
    print(f"Total errors: {total_errors}")
