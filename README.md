# Blog Code

Jupyter notebooks from the *Threat Hunting with Python* series I wrote in 2017
and 2018, brought up to date so they still run. Each notebook works through a
hunt on a real dataset that ships with the repo: a day of Bro HTTP logs from
the 2015 4SICS conference lab network, and a packet capture of Microsoft SQL
Server traffic between a historian and its clients.

The posts themselves lived on dgunter.com, which is offline, and were
syndicated on the Dragos blog. They are preserved under [docs/](docs/) with
their images so the code has its narrative next to it.

## The notebooks

| Notebook | The hunt | Companion post |
| --- | --- | --- |
| [Bro HTTP Nmap Indicator Detection](Bro%20HTTP%20Log%20Analysis/Bro%20HTTP%20Nmap%20Indicator%20Detection.ipynb) | Stack user agents and URIs, search for the Nmap Scripting Engine, and export every request between scanner and target as CSV | [Prologue and Basic HTTP Hunting](docs/2017-09-threat-hunting-with-python-prologue.md) (2017-09) |
| [Detecting Nmap Behavior with Bro HTTP Logs](Bro%20HTTP%20Log%20Analysis/Detecting%20Nmap%20Behavior%20with%20Bro%20HTTP%20Logs.ipynb) | The same log as a time series: user agents and status codes per minute, with the scan window standing out once the busy browser is removed | [Part 2: Detecting Nmap Behavior with Bro HTTP Logs](docs/2017-11-threat-hunting-with-python-part-2-nmap-bro-http.md) (2017-11) |
| [Detecting Nmap Behavior with ParseZeekLogs](Bro%20HTTP%20Log%20Analysis/Detecting%20Nmap%20Behavior%20with%20ParseZeekLogs.ipynb) | Both hunts above redone with [ParseZeekLogs](https://github.com/dgunter/ParseZeekLogs) and pandas, added in 2026 | same two posts |
| [tds](TDS%20Analysis/tds.ipynb) | Pull TDS packet types, SQL batches and remote procedure calls out of a pcap with pyshark and look at what a historian's clients actually run | [Part 4: Examining Microsoft SQL Based Historian Traffic](docs/2018-03-threat-hunting-with-python-part-4-mssql-historian.md) (2018-03) |
| [tds-zeek](TDS%20Analysis/tds-zeek.ipynb) | The same capture through Zeek with the [zeek-tds](https://github.com/dgunter/zeek-tds) analyzer, added in 2026: reassembled messages, every procedure call with its parameters and prepared-statement SQL, read into pandas with ParseZeekLogs | [Revisiting TDS](docs/2026-09-revisiting-tds.md) (draft) |

[Part 3: Taming SMB](docs/2018-02-threat-hunting-with-python-part-3-taming-smb.md)
(2018-02) is preserved too; its examples were shown inline rather than as a
notebook.

The 2018 TDS notebook works from the packet capture with pyshark because
Zeek had no usable TDS analyzer at the time. It now does: `tds-zeek.ipynb`
runs Zeek 8.2 with the [zeek-tds](https://github.com/dgunter/zeek-tds)
package in Docker (built from `TDS Analysis/zeek/Dockerfile` on first run,
which takes a few minutes) and finds the calls the packet-by-packet approach
missed. Docker is the only extra requirement.

The 2017 notebooks split each log line on tabs and count values in
dictionaries. They were written for Python 2.7 and have been ported to run on
Python 3 with current pandas and matplotlib, otherwise as written, so the
output you see is what the posts describe. The ParseZeekLogs notebook is the
version I would write today: the log is read with typed fields by a library
that understands the Zeek format, and `groupby` does the counting. It runs
unchanged on logs from current Zeek releases (checked against Zeek 8.2.2 TSV
and JSON output); the bundled log is the original 2015 one so the results match
the posts.

## Running them

Requires Python 3.10 or newer and [uv](https://docs.astral.sh/uv/). The TDS
notebook also needs `tshark` from a current Wireshark on your `PATH`: 4.6 is
what it was verified with (`brew install wireshark` on macOS; on Ubuntu the
`ppa:wireshark-dev/stable` PPA carries the latest release, as CI uses).

```bash
uv sync
uv run jupyter lab
```

Open a notebook from the folder it lives in; each reads its data file by a
relative path. To execute everything from the command line, the way CI does:

```bash
uv run jupyter nbconvert --to notebook --execute --inplace "Bro HTTP Log Analysis/"*.ipynb "TDS Analysis/"*.ipynb
```

`uv run ruff check .` lints the code cells. The Zeek notebook needs Docker; it
builds the `zeek-tds:0.2.0` image on first run. The GitHub Actions workflow runs
the lint and executes every notebook on each push and pull request, and fails
if any cell errors or writes to stderr.

## Data

- `Bro HTTP Log Analysis/http.log`: 5,758 HTTP records from one day of the
  4SICS 2015 lab network, in Bro TSV format.
- `Bro HTTP Log Analysis/suspicious_http_records.csv` and
  `suspicious_http_records_parsezeeklogs.csv`: the 299 requests between the
  scanning clients and their targets, as written by the two notebooks.
- `TDS Analysis/ms-sql-tds-rpc-requests.pcap`: 30 TDS packets between a
  Microsoft SQL Server historian and its clients.

## Related

- [ParseZeekLogs](https://github.com/dgunter/ParseZeekLogs): read Zeek logs
  as typed records, or load them into Elasticsearch in Elastic Common Schema.
- [evtxtoelk](https://github.com/dgunter/evtxtoelk): the same idea for
  Windows Event Logs.

## License

MIT, see [LICENSE](LICENSE). The posts under `docs/` are my own writing,
reproduced from the Wayback Machine.
