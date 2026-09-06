# Revisiting TDS: from tshark to a Zeek analyzer

*Draft, September 2026. Follows [Threat Hunting with Python Part 4: Examining Microsoft SQL Based Historian Traffic](2018-03-threat-hunting-with-python-part-4-mssql-historian.md) (2018).*

In 2018 I wrote about pulling Microsoft SQL Server traffic apart to see what a
historian's clients were actually asking it. The tool was tshark, driven from a
Jupyter notebook through pyshark, and the approach was to walk every packet,
read the TDS fields Wireshark exposed, and drop them into a pandas frame. It
worked, and it still runs today; the notebook is in this repository, ported to
Python 3.

It also had a ceiling I did not see at the time. Eight years later I went back
to the same capture with a different tool and found calls I had never known were
there. This post is about what was hiding, why a packet dissector cannot show
it, and what a protocol analyzer written for Zeek does instead.

## What the 2018 notebook saw

Tabular Data Stream is the protocol every SQL Server client speaks. It has a
small header and a body whose meaning depends on the message type: a SQL batch
is UTF-16 text, a remote procedure call is a procedure name or number followed
by typed parameters, a response is a stream of tokens. Wireshark's dissector
handles all of that per packet, and the 2018 notebook picked out three things:
the TDS packet type, the query text of batches, and for RPCs the procedure name
or its number.

That gave a table of 30 packets: three plain SQL batches, eight procedures
called by name, seven called by number, and a dozen server responses. The
numbers were the interesting part. `sp_prepexec` and `sp_execute` are how
drivers run prepared statements, so seven of the calls were application SQL
whose text I could not read from the columns I had extracted. I mapped the
numbers to names with a dictionary and moved on.

## What was missing

Two things, both structural.

The first is reassembly. One of the calls in the capture, `p_SaveExample`,
carries an 8 KB `nvarchar(max)` argument and arrives in two TDS packets.
Wireshark dissects each packet on its own and does not reassemble TDS
messages, so it showed two RPC frames with no procedure name in either. The
notebook counted them as blanks.

The second is that a TDS message can hold more than one call. A 53-byte RPC
message in the capture carries two `sp_execute` calls separated by a batch
flag. Wireshark reports the first procedure in a packet; the second never
appeared.

Neither is a bug in tshark. A packet dissector shows you packets. The things I
wanted to count were messages and calls, and those are one layer up.

## Doing it in Zeek

Zeek reads a TCP connection as a stream and hands it to a protocol analyzer
that knows where messages begin and end. There was a TDS analyzer for Zeek, a
2019 BinPAC plugin, but it had fallen behind Zeek's build and misread the
numbered procedures, so I wrote a new one in Spicy, Zeek's current parser
language: [zeek-tds](https://github.com/dgunter/zeek-tds).

It reassembles messages across packets and across MARS sessions, resolves the
numbered procedures, renders every parameter by type, follows the response
tokens, and hands sessions that negotiate encryption to Zeek's SSL analyzer. It
writes logs rather than a packet list: one line per login, per batch, per
procedure call, per server error, per result set. Every line carries Zeek's
connection identifier, so a SQL statement sits next to the connection it
travelled in, the TLS certificate if there was one, and the NTLM exchange if
the login was a Windows one.

Run over the 2009 capture, `tds_rpc.log` has seventeen procedure calls: the
eight named ones, the seven numbered ones, the call that spanned two packets,
and the second call in the double message. For the prepared statements it
lifts the SQL text out of the parameter that carries it:

```
procedure   sp_prepexec
statement   select * from test_table_1 where name = @P0 and id = @P1
handle      0

procedure   sp_execute
handle      2

procedure   sp_prepexec
statement   create table newsyb (column1 char(30) not null, column2 char(30) null,column3 char(30) null)
```

And for the historian's own procedures it shows what they were asked for:

```
p_GetBogusData
    @SearchType intn(1) = 1
    @MaxWaitTimeInSeconds intn(4) = 0
    @ProcessNegativeAck intn(1) = 0

proc_GetMyExampleTableSampleMetaData
    @p1 uniqueidentifier = 00112233-4455-6677-8899-AABBCCDDEEFF
    @p4 varchar(36) = ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
    @p7 varbinary(12) = 0x0123456789ABCDEFFEDCBA98
```

The notebook that does this, `tds-zeek.ipynb`, is next to the 2018 one. It
runs Zeek in Docker over the capture, reads the logs with ParseZeekLogs, and
reproduces the post's analysis in a handful of pandas calls.

## Why it matters for a hunt

The point of the 2018 post was that a historian's SQL traffic tells you what
the plant's systems are doing, and that anything outside the normal set of
procedures is worth a look. That is still true, and the analyzer is built for
it. On a sensor it answers, continuously and for every session: who connected,
from which host and with which driver; whether the login succeeded, and if
not why; what they ran and what they called, with the SQL inside prepared
statements; what the server refused; how much came back. It raises notices for
login brute force, `xp_cmdshell` and its relatives, PRELOGIN scanning, and
results far larger than normal, and a coverage table maps each log and notice
to ATT&CK and ICS ATT&CK techniques.

The honest limit is encryption. Where client and server agree on TLS, only the
login negotiation and the certificate are visible. The plaintext decoding
matters most exactly where the 2018 post lived: control-system networks where
the historian's clients still speak in the clear.

## Try it

- The notebook: [TDS Analysis/tds-zeek.ipynb](../TDS%20Analysis/tds-zeek.ipynb), and the 2018 original beside it.
- The analyzer: [github.com/dgunter/zeek-tds](https://github.com/dgunter/zeek-tds), `zkg install zeek-tds` on Zeek 7 or 8.
- The log reader: [github.com/dgunter/ParseZeekLogs](https://github.com/dgunter/ParseZeekLogs).
