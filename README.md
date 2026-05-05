# RISM Matomo Log Importer

The JSON format used by our nginx server was not compatible with the existing Matomo logs importer, and was a bit
of a mess modifying it to support it. The format we use is compatible with our Grafana log analyzer.

The primary importer is now a Go CLI. It preserves the existing command-line arguments from the Python script:

```sh
go run ./cmd/import_logs --config config-muscat.toml --dry-run /path/to/log.json
```

or, after building:

```sh
go build -o import_logs ./cmd/import_logs
./import_logs --config config-muscat.toml /path/to/log.json
```

It supports plain, gzip, and bzip2 logs; config-driven filtering; CIDR exclusions; custom dimensions; Matomo batching;
and bot detection based on the Matomo device-detector regex list.

## Bot Regex Data

The importer reads bot regex data from `bots.json`. Refresh the dataset with:

```sh
go run ./cmd/create_bots
```

Or build the generator binary first:

```sh
go build -o create_bots ./cmd/create_bots
./create_bots --output bots.json
```

The generated `bots.json` is a structured file that separates exact literal bot strings from regex-only patterns so the importer can use a fast literal matcher before falling back to `regexp2`.
