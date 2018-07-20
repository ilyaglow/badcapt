About
-----

Badcapt will try to detect *bad* packets and export them to the Elastic storage.

Only Mirai botnet scans are supported by now, [inspired by](https://mirai.badpackets.net/about/) `@Bad_Packets`.

Install
-------

```
go get github.com/ilyaglow/badcapt/cmd/badcapt
```

Usage
-----

```
./badcapt -h
Usage of badcapt:
  -e string
    	Elastic URL (default "http://localhost:9200")
  -i string
    	Interface name to listen
```

You can also [take a look at](https://github.com/ilyaglow/badcapt/tree/master/cmd/badsearch) `badsearch` - a simple daily records dumper script
