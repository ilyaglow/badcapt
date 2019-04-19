[![Build Status](https://travis-ci.org/ilyaglow/badcapt.svg?branch=master)](https://travis-ci.org/ilyaglow/badcapt)
[![](https://godoc.org/github.com/ilyaglow/badcapt?status.svg)](http://godoc.org/github.com/ilyaglow/badcapt)

About
-----

Badcapt is a project inspired by `@Bad_Packets` work. It will try to detect
*bad* packets and export them to the Elastic storage or output to the screen.

Install
-------

The app is built on top of `gopacket` package which provides C bindings for the
`libpcap`, so you should have `libpcap-dev` package installed first.

```
go get github.com/ilyaglow/badcapt/cmd/badcapt
```

Usage
-----

```
./badcapt -h
Usage of badcapt:
  -e string
    	Elasticsearch URL
  -i string
    	Interface name to listen
```

If no Elasticsearch URL provided, badcapt will simply output records to the
screen.

You can also take a look at
[badsearch](https://github.com/ilyaglow/badcapt/tree/master/cmd/badsearch):
it dumps all records in the database for the last 24 hours.
