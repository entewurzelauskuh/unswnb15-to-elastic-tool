import glob
import os
import ssl
import argparse
import urllib3
import json
import logging
import urllib.request
import base64
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.HTTPResponse)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script to import TON_IoT data from CSV into elasticsearch.")
    parser.add_argument("-e --es_host", dest="es_host", type=str, default="127.0.0.1",
                        help="Address to the elasticsearch instance. Defaults to 127.0.0.1/localhost.")
    parser.add_argument("-po --es_port", dest="es_port", type=int, default=9200,
                        help="Port of the elasticsearch instance. Defaults to 9200.")
    parser.add_argument("-u --es_user", dest="es_user", type=str, required=True,
                        help="Username of elasticsearch account which has to have write access to the target index. "
                             "Required.")
    parser.add_argument("-pa --es_password", dest="es_password", type=str, required=True,
                        help="Password of elasticsearch account. Required.")
    parser.add_argument("-i --es_index", dest="es_index", type=str, required=True,
                        help="Target index to write into. Required.")
    parser.add_argument("-m --http_method", dest="http_method", type=str, default="https",
                        help="Specify http method. Default method is https.")
    parser.add_argument("-l --logging", dest="logging", default="INFO",
                        help="Set logging severity. Defaults to INFO.")
    params = parser.parse_args()

    ES_HOST = params.es_host
    ES_PORT = params.es_port
    ES_USER = params.es_user
    ES_PW = params.es_password
    INDEX_NAME = params.es_index
    HTTP_METHOD = params.http_method
    LOGGING = params.logging

    # Create logging instance with file output
    LOG_FORMATTER = logging.Formatter(fmt="%(asctime)s :: %(levelname)s :: %(message)s", datefmt="%H:%M:%S")
    LOGGER = logging.getLogger(__name__)

    FILE_HANDLER = logging.FileHandler(Path(f"./run-{datetime.now().strftime('%d-%m-%YT%H-%M-%S')}.log"))
    FILE_HANDLER.setFormatter(LOG_FORMATTER)
    LOGGER.addHandler(FILE_HANDLER)

    CONSOLE_HANDLER = logging.StreamHandler()
    CONSOLE_HANDLER.setFormatter(LOG_FORMATTER)
    LOGGER.addHandler(CONSOLE_HANDLER)

    if LOGGING == "DEBUG":
        LOGGER.setLevel(logging.DEBUG)
    elif LOGGING == "WARNING":
        LOGGER.setLevel(logging.WARNING)
    elif LOGGING == "ERROR":
        LOGGER.setLevel(logging.ERROR)
    elif LOGGING == "CRITICAL":
        LOGGER.setLevel(logging.CRITICAL)
    else:
        LOGGER.setLevel(logging.INFO)

    # Reading in the csv files
    folder = "./data/"
    os.chdir(Path(folder))
    li = []
    for file in glob.glob("*.csv"):
        LOGGER.info(f"Found file '{file}'! Loading ...")
        df = pd.read_csv(filepath_or_buffer=file, sep=",", names=["srcip", "sport", "dstip", "dsport", "proto",
                                                                  "state", "dur", "sbytes", "dbytes", "sttl", "dttl",
                                                                  "sloss", "dloss", "service", "Sload", "Dload",
                                                                  "Spkts", "Dpkts", "swin", "dwin", "stcpb", "dtcpb",
                                                                  "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
                                                                  "Sjit", "Djit", "Stime", "Ltime", "Sintpkt",
                                                                  "Dintpkt", "tcprtt", "synack", "ackdat",
                                                                  "is_sm_ips_ports", "ct_state_ttl",
                                                                  "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
                                                                  "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
                                                                  "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
                                                                  "ct_dst_src_ltm", "attack_cat", "Label"],
                         engine="python")
        if not DISABLE_LOGGING: LOGGER.info(f"{df.info()}")
        if not DISABLE_LOGGING: LOGGER.info(f"{df.to_string(max_rows=10, max_cols=100)}")
        li.append(df)
    if not li:
        LOGGER.error("Couldn't find any csv file in the data folder, aborting.")
        exit(1)
    df = pd.concat(li, axis=0, ignore_index=True)
    li = []     # Clear memory

    LOGGER.info("Finished loading, preprocessing ...")
    # Fill NaN values with a 0
    df.fillna(0, inplace=True)
    # Replace empty and whitespace values with a 0
    df.replace(["", " "], 0, inplace=True)
    # Replace minus characters with a 0
    df["sport"] = df["sport"].apply(lambda x: "0" if "-" in x else x)
    df["dsport"] = df["dsport"].apply(lambda x: "0" if "-" in x else x)
    # Replace occurrences of port numbers which are written in hex with their decimal values
    df["sport"] = df["sport"].apply(lambda x: int(x, 16) if "x" in x else x)
    df["dsport"] = df["dsport"].apply(lambda x: int(x, 16) if "x" in x else x)
    # Adjust DType of DataFrame columns
    df = df.astype({"sport": np.uint16,
                    "dsport": np.uint32,
                    "sbytes": np.uint32,
                    "dbytes": np.uint32,
                    "sttl": np.uint32,
                    "dttl": np.uint32,
                    "sloss": np.uint32,
                    "dloss": np.uint32,
                    "Spkts": np.uint32,
                    "Dpkts": np.uint32,
                    "swin": np.uint32,
                    "dwin": np.uint32,
                    "stcpb": np.uint64,
                    "dtcpb": np.uint64,
                    "smeansz": np.uint16,
                    "dmeansz": np.uint16,
                    "res_bdy_len": np.uint32,
                    "trans_depth": np.uint8,
                    "Stime": np.uint32,
                    "Ltime": np.uint32,
                    "is_sm_ips_ports": np.uint8,
                    "ct_state_ttl": np.uint8,
                    "ct_flw_http_mthd": np.uint8,
                    "is_ftp_login": np.uint8,
                    "ct_ftp_cmd": np.uint8,
                    "ct_srv_src": np.uint8,
                    "ct_srv_dst": np.uint8,
                    "ct_dst_ltm": np.uint8,
                    "ct_src_ltm": np.uint8,
                    "ct_src_dport_ltm": np.uint8,
                    "ct_dst_sport_ltm": np.uint8,
                    "ct_dst_src_ltm": np.uint8,
                    "Label": np.uint8})
    # Sort the DataFrame by Stime
    df.sort_values(by=["Stime"], inplace=True, ignore_index=True)
    LOGGER.info("Finished!")
    LOGGER.debug(f"\n{df.to_string(max_rows=10, max_cols=100)}")
    LOGGER.debug(f"\n{df.dtypes}")

    count = 0
    LOGGER.info(f"Ready to send {df.shape[0]} docs to cluster, Starting!")
    # Begin creating one request body per DataFrame row and send it to elastic search
    for index, row in df.iterrows():
        count = count + 1
        if count % 5000 == 0:
            LOGGER.info(f"{count / df.shape[0] * 100:.2f}% ...")

        if row["Label"] == 1:
            attack = "attack"
        else:
            attack = "valid"

        if row["attack_cat"] == 0:
            attack_cat = "valid"
        else:
            attack_cat = row["attack_cat"]

        if "\ufeff" in row["srcip"]:
            row["srcip"] = row["srcip"].replace("\ufeff", "")

        body = {
            "@timestamp": datetime.utcfromtimestamp(row["Stime"]).strftime('%Y-%m-%dT%H:%M:%S'),
            "@version": "1",
            "ecs": {
                "version": "1.5.0"
            },
            "event": {
                "kind": "event",
                "dataset": "flow",
                "action": "network_flow",
                "category": "network_traffic",
                "start": datetime.utcfromtimestamp(row["Stime"]).strftime("%Y-%m-%dT%H:%M:%S"),
                "end": datetime.utcfromtimestamp(row["Ltime"]).strftime("%Y-%m-%dT%H:%M:%S"),
                "duration": row["dur"] * 1000000000
            },
            "source": {
                "ip": row["srcip"],
                "port": row["sport"],
                "bytes": row["sbytes"]
            },
            "destination": {
                "ip": row["dstip"],
                "port": row["dsport"],
                "bytes": row["dbytes"]
            },
            "network": {
                "transport": row["proto"],
                "type": "ipv4",
                "bytes": row["sbytes"] + row["dbytes"],
                "packets": row["Spkts"] + row["Dpkts"]
            },
            "http": {
                "response": {
                    "bytes": row["res_bdy_len"]
                }
            },
            "zeek": {
                "http": {
                    "trans_depth": row["trans_depth"]
                }
            },
            "Argus": {
                "source": {
                    "packet_count": row["Spkts"],
                    "ttl": row["sttl"],
                    "loss": row["sloss"],
                    "load": row["Sload"],
                    "packet_mean_size": row["smeansz"],
                    "jitter": row["Sjit"],
                    "interpacket_time": row["Sintpkt"],
                },
                "destination": {
                    "packet_count": row["Dpkts"],
                    "ttl": row["dttl"],
                    "loss": row["dloss"],
                    "load": row["Dload"],
                    "packet_mean_size": row["dmeansz"],
                    "jitter": row["Djit"],
                    "interpacket_time": row["Dintpkt"],
                },
                "tcp": {
                    "rtt": row["tcprtt"],
                    "synack": row["synack"],
                    "ackdat": row["ackdat"],
                    "source": {
                        "window": row["swin"],
                        "sequence": row["stcpb"],
                    },
                    "destination": {
                        "window": row["dwin"],
                        "sequence": row["dtcpb"]
                    }
                }
            },
            "additional_general_purpose": {
                "is_sm_ips_ports": row["is_sm_ips_ports"],
                "ct_state_ttl": row["ct_state_ttl"],
                "ct_flw_http_mthd": row["ct_flw_http_mthd"],
                "is_ftp_login": row["is_ftp_login"],
                "ct_ftp_cmd": row["ct_ftp_cmd"]
            },
            "additional_connection": {
                "ct_srv_src": row["ct_srv_src"],
                "ct_srv_dst": row["ct_srv_dst"],
                "ct_dst_ltm": row["ct_dst_ltm"],
                "ct_src_ltm": row["ct_src_ltm"],
                "ct_src_dport_ltm": row["ct_src_dport_ltm"],
                "ct_dst_sport_ltm": row["ct_dst_sport_ltm"],
                "ct_dst_src_ltm": row["ct_dst_src_ltm"]
            },
            "attack": {
                "category": attack_cat,
                "label": row["Label"]
            },
            "tags": ["UNSW-NB15", attack],
            "type": "flow"
        }
        if "-" not in row["service"]:
            body["network"]["protocol"] = row["service"]
        if "-" not in row["state"]:
            body["Argus"]["transaction"] = {"state": row["state"]}

        LOGGER.debug(f"Sending {body}")

        elastic_target = f"{HTTP_METHOD}://{ES_HOST}:{ES_PORT}/{INDEX_NAME}/_doc"
        req = urllib.request.Request(elastic_target)
        json_data = json.dumps(body)
        json_data_as_bytes = json_data.encode("utf-8")
        credentials = base64.b64encode(f"{ES_USER}:{ES_PW}".encode("utf-8")).decode("utf-8")
        req.add_header("Authorization", f"Basic {credentials}")
        req.add_header("Content-Type", "application/json; charset=utf-8")
        req.add_header("Content-Length", len(json_data_as_bytes))
        ssl._create_default_https_context = ssl._create_unverified_context
        response = urllib.request.urlopen(req, json_data_as_bytes)
        LOGGER.debug(f"Response {json.loads(response.read().decode('utf-8'))}")

    LOGGER.info("All done! Please check your index for completeness.")
