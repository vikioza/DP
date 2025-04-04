import glob
import pyshark
import time

import pandas as pd
from datetime import datetime, timezone

from sniffer.packet import PacketInfo


CSV_DIR = "C:\VScode_Projects\DP\datasets\CIC-DDoS-2019\\raw\csv\\03-11"
PCAP_DIR = "C:\VScode_Projects\DP\datasets\CIC-DDoS-2019\\raw\pcap\PCAP-03-11"
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


def read_csv(dir: str, cols: list = None):
    print("READING CSV FILES...")

    extension = "*.csv"
    files = glob.glob(f"{dir}/{extension}")

    dfs = []
    for file in files:
        print(f"READING {file}")
        if cols:
            dfs.append(pd.read_csv(file, usecols=cols))
        else:
            dfs.append(pd.read_csv(file))

    print("MERGING CSV FILES...")
    df = pd.concat(dfs, ignore_index=True)
    df.columns = df.columns.str.strip()

    print('DROPPING ROWS WITH MISSING "Flow ID"...')
    df = df.drop(df[pd.isnull(df["Flow ID"])].index)

    # print(f"\nUNIQUE LABELS:")
    # print(df.Label.unique())
    # print(f"\nLABEL COUNTS:")
    # print(df.Label.value_counts())

    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    min_timestamp = df["Timestamp"].min()

    return df, min_timestamp


def parse_pcap(dir, df: pd.DataFrame, ts, start_time: float):
    print("PARSING PCAP FILES...")

    packet_count = 0
    wrong_protocol = 0
    error_count = 0
    capture_start_time = (
        datetime.fromisoformat(str(ts)).replace(tzinfo=timezone.utc).timestamp()
    )

    with open(
        "C:\VScode_Projects\DP\datasets\CIC-DDoS-2019\clean\sample.csv", "w"
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

        files = glob.glob(f"{dir}/*")
        for file in files:
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
                        if packet_count % 10_000 == 0:
                            print(f"COUNT: {packet_count}")

                            f.writelines(out)
                            out = []

                            current_time = time.time()
                            print(f"RUNTIME: {current_time-start_time:.2f} (seconds)")

                    else:
                        wrong_protocol += 1

                except TypeError as te:
                    print(f"TypeError: {te}")
                    error_count += 1
                    continue

                except AttributeError as te:
                    print(f"AttributeError: {te}")
                    error_count += 1
                    continue

        print(f"Total number of tcp/udp packets: {packet_count}")
        print(f"Total number of other packets: {wrong_protocol}")
        print(f"Total number of errors: {error_count}")
        current_time = time.time()
        print(f"Total runtime: {(current_time-start_time)/60:.2f} (minutes)")


if __name__ == "__main__":
    start_time = time.time()
    df, ts = read_csv(CSV_DIR, cols=COLS)
    parse_pcap(PCAP_DIR, df, ts, start_time)
