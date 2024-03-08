# RISM Matomo Log Importer

The JSON format used by our nginx server was not compatible with the existing Matomo logs importer, and was a bit 
of a mess modifying it to support it. The format we use is compatible with our Grafana log analyzer.

This log importer is lightweight but provides more features than the official one. Namely, it supports custom
dimensions, a config file format, threaded log processing, and better bot detection. It has only one dependency, ujson, 
to support fast JSON reading and writing.

On the minus side, it only supports uploading one log file at a time.

The virtual environment for it is managed with Poetry, like all other scripts we write. 
