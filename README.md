[![Build Status](https://travis-ci.org/ilyaglow/badcapt.svg?branch=master)](https://travis-ci.org/ilyaglow/badcapt)
[![](https://godoc.org/github.com/ilyaglow/badcapt?status.svg)](http://godoc.org/github.com/ilyaglow/badcapt)

About
-----

Badcapt is a project inspired by
[Bad Packets'](https://badpackets.net) work and the
[Remote Identification of Port Scan Toolchains](http://pure.tudelft.nl/ws/files/10611227/10611102.pdf)
paper by Vincent Ghiette, Norbert Blenn, Christian Doerr.

It will try to detect malicious packets and export them to the Elastic storage or
output to the stdout for your further processing.

Install
-------

The app is built on top of `gopacket` package which provides C bindings for the
`libpcap`, so you should have `libpcap-dev` package installed first.

```
go get github.com/ilyaglow/badcapt/cmd/badcapt
```

Also you can use the docker image (see below on how to use it):
```
docker build -t badcapt https://github.com/ilyaglow/badcapt.git
```
or
```
docker pull ilyaglow/badcapt
```

Usage
-----

```
./badcapt -h
Usage of badcapt:
  -e string
    	Elasticsearch URL (optional)
  -i string
    	Interface name to listen
  -ns string
    	Path to nmap-services file, by default on linux it's /usr/share/nmap/nmap-services
```

If no Elasticsearch URL provided, badcapt will simply output records to stdout.

To use the dockerized version you must run it with `--net=host` switch:
```
docker run -d --net=host ilyaglow/badcapt -i eth0
```

You can also take a look at the
[badsearch](https://github.com/ilyaglow/badcapt/tree/master/cmd/badsearch)
companion script for the Elasticsearch: it dumps all records in the database for
the last 24 hours.
