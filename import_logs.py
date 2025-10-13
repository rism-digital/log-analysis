import argparse
import concurrent.futures
import fnmatch
import gzip
import ipaddress
import itertools
import logging
import re
import sys
import tomllib
import urllib.parse
from collections import deque
from contextlib import contextmanager
from typing import NotRequired, TypedDict

import httpx

# import requests
import ujson
from netaddr import IPAddress, IPSet

import bots

logging.basicConfig(
    format="[%(asctime)s] [%(levelname)8s] %(message)s (%(filename)s:%(lineno)s)"
)
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


def compile_all_bot_regexes():
    joined_bots = f"({'|'.join(bots.botua)})"
    return re.compile(joined_bots)


# make this a top-level variable so we don't have to pass it around.
compiled_bot_regexes = compile_all_bot_regexes()
compiled_cidr_rules = None


def batched(iterable, n):
    it = iter(iterable)
    while batch := tuple(itertools.islice(it, n)):
        yield batch


class Hit(TypedDict):
    url: str  # page URL
    urlref: str  # referring URL
    ua: str  # user agent
    dimensions: NotRequired[list[str]]  # custom dimensions
    cdt: str  # datetime
    cip: str  # Client IP
    country: str  # Country code (lowercase)
    city: str
    lat: str
    long: str
    pf_srv: str  # request time
    bw_bytes: str  # response body size
    apiv: str  # API Version, must be 1
    rec: str  # "Required for tracking, must be 1"
    idsite: str  # The matomo site
    queuedtracking: str  # set to 0 because the official log shipper was.
    dp: str  # 1 disables DNS lookups
    dimension1: str
    dimension2: str


def get_ip_address(parsed_line: dict) -> str:
    x_forwarded: str | None = parsed_line.get("http_x_forwarded_for")
    remote = parsed_line["remote_addr"]

    if not x_forwarded:
        return remote

    if "," in x_forwarded:
        # Proxies can add themselves to the list of XFF headers.
        # See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For
        # We're only interested in the first (for now).
        all_clients: list = x_forwarded.split(", ")
        x_forwarded = all_clients[0]

    try:
        ipaddress.ip_address(x_forwarded)
    except ValueError:
        log.info("Could not parse x-forwarded value: %s", x_forwarded)
        return remote

    return x_forwarded


def create_hit(parsed_line: dict, idsite: str) -> Hit:
    host: str = parsed_line.get("http_host", "")
    scheme: str = parsed_line.get("scheme", "")
    path: str = parsed_line.get("request_uri", "")

    if path.startswith("//"):
        path = path.replace("//", "/")

    url = f"{scheme}://{host}{path}"
    ip_address: str = get_ip_address(parsed_line)

    # Matomo treats the + as a URL space character, so URL encode it.
    accept_header: str = parsed_line.get("http_accept", "").replace("+", "%2b")

    h: Hit = {
        "url": url,
        "urlref": parsed_line.get("http_referer", ""),
        "ua": parsed_line.get("http_user_agent", ""),
        "dimension1": accept_header,
        "dimension2": parsed_line.get("status", ""),
        "cdt": parsed_line.get("time_iso8601", ""),
        "cip": ip_address,
        "country": parsed_line.get("geoip_country_code", "").lower(),
        "city": parsed_line.get("geoip_city", ""),
        "lat": parsed_line.get("geoip_latitude", ""),
        "long": parsed_line.get("geoip_longitude", ""),
        "pf_srv": parsed_line.get("request_time", ""),
        "bw_bytes": parsed_line.get("bytes_sent", ""),
        "apiv": "1",
        "rec": "1",
        "idsite": idsite,
        "queuedtracking": "0",
        "dp": "1",
    }

    return h


def submit_hit(batch: tuple, cfg: dict, client: httpx.Client) -> bool:
    matomo_url = f"{cfg['matomo']['url']}/piwik.php"
    req_data: dict = {
        "token_auth": cfg["matomo"]["auth_token"],
        "requests": list(batch),
    }

    json_data: str = ujson.dumps(req_data)
    log.debug("Size of request body: %s KB", sys.getsizeof(json_data) * 0.001)

    response = client.post(
        url=matomo_url,
        content=json_data.encode("utf-8"),
        headers={"Content-Type": "application/json"},
        timeout=600,
    )

    if response.status_code != 200:
        log.error("Request failed: %s %s", response.status_code, response.reason_phrase)
        return False

    log.debug("Actual status code: %s", response.status_code)

    return True


def apply_line_filters(json_record: dict, cfg: dict) -> bool:
    url_path: str = json_record.get("request_uri", "")
    if url_path.startswith("//"):
        url_path = url_path.replace("//", "/")

    request_id: str = json_record.get("request_id", "")
    url_components = urllib.parse.urlparse(url_path)

    log.debug("checking if request %s needs to be filtered out", request_id)

    for exclude_path in cfg["exclude"]["paths"]:
        if fnmatch.fnmatch(url_path, exclude_path):
            log.debug("filtering %s: Path was excluded: ID: %s", url_path, request_id)
            return False
        log.debug("passing %s on to the next filter: ID: %s", url_path, request_id)

    if url_components.path.endswith(tuple(cfg["exclude"]["extensions"])):
        log.debug("filtering %s: Extension was excluded: ID: %s", url_path, request_id)
        return False

    log.debug("passed extension check: ID: %s", request_id)

    if cfg["exclude"]["bots"]:
        user_agent: str = json_record.get("http_user_agent", "")
        if user_agent and re.search(compiled_bot_regexes, user_agent) is not None:
            log.debug(
                "filtering %s: User agent is a bot. ID: %s", user_agent, request_id
            )
            return False

        log.debug("keeping %s: User agent is not a bot. ID: %s", user_agent, request_id)

    if compiled_cidr_rules is not None:
        this_ip = get_ip_address(json_record)
        this_address = IPAddress(this_ip)
        if this_address in compiled_cidr_rules:
            log.debug("filtering IP address %s: ID %s", this_address, request_id)
            return False

    log.debug("keeping line with request ID %s", json_record.get("request_id"))
    return True


def parse_line(line: str, lineno: int, cfg: dict) -> Hit | None:
    log.debug("Processing line %s", lineno)

    idsite: str = cfg["matomo"]["idsite"]
    line = line.replace("\\x", "\\u00")
    json_record: dict = ujson.loads(line)
    keep_line: bool = apply_line_filters(json_record, cfg)

    if not keep_line:
        return None

    log.debug("creating hit for line with request ID %s", json_record.get("request_id"))
    return create_hit(json_record, idsite)


_GZIP_MAGIC = b"\x1f\x8b"


def _is_gzip(pathlike) -> bool:
    # Works for str/PathLike
    with open(pathlike, "rb") as ff:
        return ff.read(2) == _GZIP_MAGIC


@contextmanager
def smart_open(path, mode="rt", *iargs, **kwargs):
    """
    Open a file normally, or with gzip if it is gzipped.
    Supports text/binary modes. Pass encoding/errors/newline in text mode.
    Usage: with smart_open(path, encoding="utf-8", errors="surrogateescape") as f: ...
    """
    opener = gzip.open if _is_gzip(path) else open
    ff = opener(path, mode, *iargs, **kwargs)
    try:
        yield ff
    finally:
        ff.close()


def parse_logfile(logfile_path: str, dry_run: bool, cfg: dict) -> bool:
    lineno = 0
    hits_found = 0
    filtered_hits = 0
    hits: deque[Hit] = deque()

    with (
        smart_open(logfile_path, encoding="utf-8", errors="surrogateescape") as logfile,
        concurrent.futures.ThreadPoolExecutor() as executor,
    ):
        max_in_flight = 4 * executor._max_workers  # tune as needed
        in_flight: deque = deque()

        def submit_more():
            nonlocal lineno
            while len(in_flight) < max_in_flight:
                line = logfile.readline()
                if not line:
                    break
                lineno += 1
                in_flight.append(executor.submit(parse_line, line, lineno, cfg))
                if lineno % 1000 == 0:
                    log.info("Read %s lines", lineno)

        submit_more()
        while in_flight:
            fut = in_flight.popleft()
            try:
                result = fut.result()
                if result is not None:
                    hits_found += 1
                    hits.append(result)
                else:
                    filtered_hits += 1
            except Exception as e:
                log.error("An exception occurred: %s", e)
            submit_more()

    log.info("Found %s lines", lineno)
    log.info("Filtered %s", filtered_hits)
    log.info("Submitting %s results", hits_found)

    success = True
    if dry_run:
        log.info("Dry run. Exiting before submitting results")
        return success

    batch_size: int = cfg["matomo"]["batch_size"]
    count = 0

    proxies = None
    if p := cfg["matomo"].get("https_proxy", None):
        proxies = {"https://": httpx.HTTPTransport(proxy=p)}

    client = httpx.Client(mounts=proxies)

    for batch in batched(hits, batch_size):
        success &= submit_hit(batch, cfg, client)
        count += len(batch)
        log.info("Submitted %s records", count)

    if not success:
        log.error("Some uploads failed. Please see the log messages.")

    return success


def main(logfiles: list[str], dry_run: bool, cfg: dict) -> bool:
    success: bool = True

    for lf in logfiles:
        log.info("Processing file %s", lf)
        try:
            success &= parse_logfile(lf, dry_run, cfg)
        except Exception as e:
            log.error("Error opening file %s: %s", lf, e)
            success &= False
            continue

    return success


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "logfiles", type=str, nargs="+", help="Path to the nginx logfile"
    )
    parser.add_argument("--config", "-c", default="config.toml", help="The config file")
    parser.add_argument(
        "--debug", "-d", action="store_true", help="Enable debug messages"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose messages"
    )
    parser.add_argument(
        "--dry-run",
        "-r",
        action="store_true",
        help="Process all records but do not submit them.",
    )

    args: argparse.Namespace = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
    elif args.verbose:
        log.setLevel(logging.INFO)
    else:
        log.setLevel(logging.WARNING)

    with open(args.config, "rb") as f:
        outer_cfg: dict = tomllib.load(f)

    if outer_cfg["exclude"]["addresses"]:
        compiled_cidr_rules = IPSet(outer_cfg["exclude"]["addresses"])

    overall_success = main(args.logfiles, args.dry_run, outer_cfg)
    if not overall_success:
        sys.exit(-1)

    sys.exit()
