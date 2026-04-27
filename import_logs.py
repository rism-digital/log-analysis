import argparse
import bz2
import fnmatch
import gzip
import ipaddress
import itertools
import logging
import sys
import tomllib
from collections import deque
from contextlib import contextmanager, nullcontext
from datetime import timedelta
from pathlib import Path
from typing import NotRequired, TypedDict

import orjson
import regex as re
from netaddr import IPAddress, IPSet
from pyreqwest.client import SyncClient, SyncClientBuilder
from pyreqwest.proxy import ProxyBuilder

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


class ExcludeConfig(TypedDict):
    paths: tuple[str, ...]
    extensions: tuple[str, ...]
    bots: bool


class ParsedLineContext(TypedDict):
    json_record: dict
    request_path: str
    request_path_only: str
    client_ip: str
    user_agent: str


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
        # Validate an IP address.
        ipaddress.ip_address(x_forwarded)  # type: ignore[arg-type]
    except ValueError:
        log.info("Could not parse x-forwarded value: %s", x_forwarded)
        return remote

    return x_forwarded  # type: ignore[return-value]


def normalize_request_path(path: str) -> str:
    if path.startswith("//"):
        return f"/{path.lstrip('/')}"
    return path


def create_hit(parsed_line: dict, idsite: str, client_ip: str, request_path: str) -> Hit:
    host: str = parsed_line.get("http_host", "")
    scheme: str = parsed_line.get("scheme", "")
    url = f"{scheme}://{host}{request_path}"

    # Matomo treats the + as a URL space character, so URL encode it.
    accept_header: str = parsed_line.get("http_accept", "").replace("+", "%2b")

    h: Hit = {
        "url": url,
        "urlref": parsed_line.get("http_referer", ""),
        "ua": parsed_line.get("http_user_agent", ""),
        "dimension1": accept_header,
        "dimension2": parsed_line.get("status", ""),
        "cdt": parsed_line.get("time_iso8601", ""),
        "cip": client_ip,
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


def submit_hit(batch: tuple, cfg: dict, client: SyncClient) -> bool:
    matomo_url = f"{cfg['matomo']['url']}/piwik.php"
    req_data: dict = {
        "token_auth": cfg["matomo"]["auth_token"],
        "requests": list(batch),
    }

    json_data: str = orjson.dumps(req_data).decode("utf-8")
    log.debug("Size of request body: %s KB", sys.getsizeof(json_data) * 0.001)

    response = (
        client.post(matomo_url)
        .headers({"Content-Type": "application/json"})
        .body_bytes(json_data.encode("utf-8"))
        .timeout(timedelta(seconds=600))
        .build()
        .send()
    )

    if response.status != 200:
        log.error("Request failed: %s %s", response.status, response.text())
        return False

    log.debug("Actual status code: %s", response.status)

    return True


def apply_line_filters(parsed_line: ParsedLineContext, exclude_cfg: ExcludeConfig) -> bool:
    json_record = parsed_line["json_record"]
    url_path = parsed_line["request_path"]
    url_path_only = parsed_line["request_path_only"]
    request_id: str = json_record.get("request_id", "")

    log.debug("checking if request %s needs to be filtered out", request_id)

    for exclude_path in exclude_cfg["paths"]:
        if fnmatch.fnmatch(url_path, exclude_path):
            log.debug("filtering %s: Path was excluded: ID: %s", url_path, request_id)
            return False
        log.debug("passing %s on to the next filter: ID: %s", url_path, request_id)

    if url_path_only.endswith(exclude_cfg["extensions"]):
        log.debug("filtering %s: Extension was excluded: ID: %s", url_path, request_id)
        return False

    log.debug("passed extension check: ID: %s", request_id)

    if exclude_cfg["bots"]:
        user_agent = parsed_line["user_agent"]
        if user_agent and re.search(compiled_bot_regexes, user_agent) is not None:
            log.debug(
                "filtering %s: User agent is a bot. ID: %s", user_agent, request_id
            )
            return False

        log.debug("keeping %s: User agent is not a bot. ID: %s", user_agent, request_id)

    if compiled_cidr_rules is not None:
        this_address = IPAddress(parsed_line["client_ip"])
        if this_address in compiled_cidr_rules:
            log.debug("filtering IP address %s: ID %s", this_address, request_id)
            return False

    log.debug("keeping line with request ID %s", json_record.get("request_id"))
    return True


def build_parsed_line_context(json_record: dict) -> ParsedLineContext:
    request_path = normalize_request_path(json_record.get("request_uri", ""))
    return {
        "json_record": json_record,
        "request_path": request_path,
        "request_path_only": request_path.split("?", 1)[0],
        "client_ip": get_ip_address(json_record),
        "user_agent": json_record.get("http_user_agent", ""),
    }


def parse_line(line: str, lineno: int, cfg: dict, exclude_cfg: ExcludeConfig) -> Hit | None:
    log.debug("Processing line %s", lineno)

    idsite: str = cfg["matomo"]["idsite"]
    if "\\x" in line:
        line = line.replace("\\x", "\\u00")
    try:
        json_record: dict = orjson.loads(line)
    except orjson.JSONDecodeError:
        log.error("Could not decode line %s", line)
        return None

    parsed_line = build_parsed_line_context(json_record)
    keep_line = apply_line_filters(parsed_line, exclude_cfg)

    if not keep_line:
        return None

    log.debug("creating hit for line with request ID %s", json_record.get("request_id"))
    return create_hit(
        json_record,
        idsite,
        parsed_line["client_ip"],
        parsed_line["request_path"],
    )


_GZIP_MAGIC = b"\x1f\x8b"
_BZ2_MAGIC = b"BZ"

PathLike = str | Path


@contextmanager
def smart_open(path: PathLike, mode="rt", *args, **kwargs):
    """
    Open a file normally, or with gzip/bz2 if compressed.
    Supports text/binary modes.

    Usage:
        with smart_open(path, encoding="utf-8", errors="surrogateescape") as f:
            ...
    """
    opener = _get_opener(path)
    logfile = opener(path, mode, *args, **kwargs)
    try:
        yield logfile
    finally:
        logfile.close()


def _get_opener(path: PathLike):
    if _is_gzip(path):
        return gzip.open
    if _is_bz2(path):
        return bz2.open
    return open


def _is_gzip(path: PathLike) -> bool:
    with open(path, "rb") as maybe_gzip:
        return maybe_gzip.read(2) == _GZIP_MAGIC


def _is_bz2(path: PathLike) -> bool:
    with open(path, "rb") as maybe_bzip:
        return maybe_bzip.read(2) == _BZ2_MAGIC


def parse_logfile(logfile_path: str, dry_run: bool, cfg: dict) -> bool:
    lineno = 0
    hits_found = 0
    filtered_hits = 0
    pending_hits: deque[Hit] = deque()
    batch_size: int = cfg["matomo"]["batch_size"]
    exclude_cfg: ExcludeConfig = {
        "paths": tuple(cfg["exclude"]["paths"]),
        "extensions": tuple(cfg["exclude"]["extensions"]),
        "bots": cfg["exclude"]["bots"],
    }
    count = 0
    success = True

    client_builder = SyncClientBuilder()
    if p := cfg["matomo"].get("https_proxy", None):
        client_builder.proxy(ProxyBuilder.https(p))

    with smart_open(logfile_path, encoding="utf-8", errors="surrogateescape") as logfile:
        client_cm = client_builder.build() if not dry_run else nullcontext(None)
        with client_cm as client:
            for line in logfile:
                lineno += 1
                if lineno % 1000 == 0:
                    log.info("Read %s lines", lineno)

                try:
                    result = parse_line(line, lineno, cfg, exclude_cfg)
                except Exception as e:
                    log.error("An exception occurred: %s", e)
                    filtered_hits += 1
                    continue

                if result is None:
                    filtered_hits += 1
                    continue

                hits_found += 1
                pending_hits.append(result)

                if dry_run or len(pending_hits) < batch_size:
                    continue

                success &= submit_hit(tuple(pending_hits), cfg, client)
                count += len(pending_hits)
                pending_hits.clear()
                log.info("Submitted %s records", count)

            if pending_hits and client is not None:
                success &= submit_hit(tuple(pending_hits), cfg, client)
                count += len(pending_hits)
                pending_hits.clear()
                log.info("Submitted %s records", count)

    log.info("Found %s lines", lineno)
    log.info("Filtered %s", filtered_hits)
    log.info("Submitting %s results", hits_found)

    if dry_run:
        log.info("Dry run. Exiting before submitting results")
        return success

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
