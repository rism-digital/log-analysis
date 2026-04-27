import argparse
import re

from pyreqwest.client import SyncClientBuilder

YML_URL = "https://raw.githubusercontent.com/matomo-org/device-detector/refs/heads/master/regexes/bots.yml"


def download_yml(url):
    with SyncClientBuilder().build() as client:
        response = client.get(url).build().send()
        response.error_for_status()
        return response.text()


def extract_regex_patterns(yml_content):
    return re.findall(r"regex:\s*'([^']+)'", yml_content)


def write_python_array(patterns, output_path):
    beginning = [
        '    r"check_ssl_cert.*"',
        '    r"synthetic-monitoring-agent.*"',
        '    r"monitoring360bot"',
    ]
    prelude = ",\n".join(beginning)
    with open(output_path, "w", encoding="utf-8") as botfile:
        botfile.write("botua = [\n")
        botfile.write(f"{prelude},\n")
        for pattern in patterns:
            botfile.write(f'    r"{pattern}",\n')
        botfile.write("]\n")


def main():
    parser = argparse.ArgumentParser(
        description="Download and extract bot regex patterns into a Python file."
    )
    parser.add_argument(
        "--output",
        "-o",
        default="bots.py",
        help="Output Python file path (default: bots.py)",
    )
    args = parser.parse_args()

    print("📥 Downloading latest bots.yml...")
    yml_content = download_yml(YML_URL)

    print("🔍 Extracting regex patterns...")
    patterns = extract_regex_patterns(yml_content)

    print(f"💾 Writing {len(patterns)} patterns to '{args.output}'...")
    write_python_array(patterns, args.output)

    print("✅ Done.")


if __name__ == "__main__":
    main()
