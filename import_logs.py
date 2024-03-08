import argparse
import concurrent.futures
import fnmatch
import itertools
import logging
import re
import sys
import tomllib
import urllib.parse
import urllib.request
from typing import TypedDict, Optional

import ujson

import bots

logging.basicConfig(format="[%(asctime)s] [%(levelname)8s] %(message)s (%(filename)s:%(lineno)s)")
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


def compile_all_bot_regexes():
    joined_bots = f"({'|'.join(bots.botua)})"
    return re.compile(joined_bots)


# make this a top-level variable so we don't have to pass it around.
compiled_bot_regexes = compile_all_bot_regexes()


def batched(iterable, n):
    it = iter(iterable)
    while batch := tuple(itertools.islice(it, n)):
        yield batch


class Hit(TypedDict):
    url: str        # page URL
    urlref: str     # referring URL
    ua: str         # user agent
    dimensions: list[str]  # custom dimensions
    cdt: str        # datetime
    cip: str        # Client IP
    country: str    # Country code (lowercase)
    city: str
    lat: str
    long: str
    pf_srv: str     # request time
    bw_bytes: str   # response body size
    apiv: str       # API Version, must be 1
    rec: str        # "Required for tracking, must be 1"
    idsite: str     # The matomo site
    queuedtracking: str  # set to 0 because the official log shipper was.
    dp: str         # 1 disables DNS lookups


def create_hit(parsed_line: dict, idsite: str) -> Hit:
    host = parsed_line.get("http_host")
    scheme = parsed_line.get("scheme")
    path = parsed_line.get("request_uri")

    url = f"{scheme}://{host}{path}"

    # Matomo treats the + as a URL space character, so URL encode it.
    accept_header: str = parsed_line.get("http_accept", "").replace("+", "%2b")

    h: Hit = {
        "url": url,
        "urlref": parsed_line.get("referrer"),
        "ua": parsed_line.get("http_user_agent"),
        "dimension1": accept_header,
        "dimension2": parsed_line.get("status"),
        "cdt": parsed_line.get("time_iso8601"),
        "cip": parsed_line.get("remote_addr"),
        "country": parsed_line.get("geoip_country_code").lower(),
        "city": parsed_line.get("geoip_city"),
        "lat": parsed_line.get("geoip_latitude"),
        "long": parsed_line.get("geoip_longitude"),
        "pf_srv": parsed_line.get("request_time"),
        "bw_bytes": parsed_line.get("bytes_sent"),
        "apiv": "1",
        "rec": "1",
        "idsite": idsite,
        "queuedtracking": "0",
        "dp": "1"
    }

    return h


def submit_hit(batch: tuple, cfg: dict) -> bool:
    matomo_url = f"{cfg['matomo']['url']}/piwik.php"
    req_data: dict = {
        "token_auth": cfg['matomo']["auth_token"],
        "requests": list(batch)
    }

    json_data = ujson.dumps(req_data)
    req = urllib.request.Request(url=matomo_url, data=json_data.encode('utf-8'),
                                 method="POST", headers={"Content-Type": "application/json"})

    log.debug(f"Size of request body: %s KB", sys.getsizeof(json_data) * 0.001)

    with urllib.request.urlopen(req) as response:
        if response.status != 200:
            log.error("Request failed: %s %s", response.status, response.reason)
            return False

    return True


def apply_line_filters(json_record: dict, cfg: dict) -> bool:
    url_path: str = json_record.get("request_uri")
    url_components = urllib.parse.urlparse(url_path)

    if url_components.path.endswith(tuple(cfg['exclude']['extensions'])):
        log.debug("filtering %s: Extension was excluded", url_path)
        return False

    for exclude_path in cfg['exclude']['paths']:
        if fnmatch.fnmatch(url_path, exclude_path):
            log.debug("filtering %s: Path was excluded", url_path)
            return False
        log.debug("passing %s on to the next filter", url_path)

    if cfg['exclude']['bots']:
        user_agent = json_record.get("http_user_agent")
        if user_agent:
            if re.search(compiled_bot_regexes, user_agent) is not None:
                log.debug("filtering %s: User agent is a bot.", user_agent)
                return False
            log.debug("keeping %s: User agent is not a bot", user_agent)

    log.debug("Keeping line with request ID %s", json_record.get("request_id"))
    return True


def parse_line(line: str, lineno: int, cfg: dict) -> Optional[Hit]:
    if lineno % 1000 == 0:
        log.info("Processing line %s", lineno)

    idsite: str = cfg['matomo']['idsite']
    line = line.replace('\\x', '\\u00')
    json_record: dict = ujson.loads(line)
    keep_line: bool = apply_line_filters(json_record, cfg)
    if not keep_line:
        return None

    return create_hit(json_record, idsite)


def main(logfile_path: str, dry_run: bool, cfg: dict) -> bool:
    with open(logfile_path, mode='rt', encoding="utf-8", errors="surrogateescape") as logfile:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            hit_futures = [executor.submit(parse_line, line, lineno, cfg) for lineno, line in enumerate(logfile, 1)]
            hits = [h.result() for h in concurrent.futures.as_completed(hit_futures)]

            log.info("Found %s hits", len(hits))
            log.info("Filtered %s", hits.count(None))

            filt_hits = [h for h in hits if h is not None]
            log.info("Submitting %s results", len(filt_hits))

    success = True
    if dry_run:
        log.info("Dry run. Exiting before submitting results")
        return success

    batch_size: int = cfg['matomo']['batch_size']
    count = 0

    for batch in batched(filt_hits, batch_size):
        success &= submit_hit(batch, cfg)
        count += len(batch)
        log.info("Submitted %s records", count)

    if not success:
        log.error("Some uploads failed. Please see the log messages.")

    return success


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile", help="Path to the nginx logfile")
    parser.add_argument("--config", "-c", default="config.toml", help="The config file")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug messages")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose messages")
    parser.add_argument("--dry-run", "-r", action="store_true", help="Process all records but do not submit them.")

    args: argparse.Namespace = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
    elif args.verbose:
        log.setLevel(logging.INFO)
    else:
        log.setLevel(logging.WARNING)

    with open(args.config, "rb") as f:
        outer_cfg: dict = tomllib.load(f)

    overall_success = main(args.logfile, args.dry_run, outer_cfg)
    if not overall_success:
        sys.exit(-1)

    sys.exit()

