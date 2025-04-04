from sniffer.alert import AlertSystem
from sniffer.flow import FlowControl

def dump_stats(
    packet_count: int,
    normal_count: int,
    mismatch_count: int,
    unrecognized_threats: int,
    skipped_count: int,
    error_count: int,
    flows: FlowControl,
    alerts: AlertSystem,
):
    print("DUMPING STATS...")
    print(f"Total received packets: {packet_count}")
    print(f"Packets skipped: {skipped_count}")
    print(f"Errors handled during runtime: {error_count}")
    print(f"Normal packets received: {normal_count}")
    print(f"Prediction mismatches: {mismatch_count}")

    unrecognized_threats += sum([alerts.threshold for _ in alerts.threats])
    print(f"Unrecognized threats detected in {unrecognized_threats} packets!")
    flows.dump_stats()
    alerts.dump_stats()
    print("EXITING...")