OpenCTF // Server
=================

The web application for [OpenCTF](https://github.com/easyctf/openctf).

[![Build Status](https://api.travis-ci.org/EasyCTF/openctf-server.svg?branch=master)](https://travis-ci.org/EasyCTF/openctf-server)
[![Coverage Status](https://coveralls.io/repos/github/EasyCTF/openctf-server/badge.svg?branch=rebuild)](https://coveralls.io/github/EasyCTF/openctf-server?branch=rebuild)

Tests
-----

To run the test suite, specify a `DATABASE_URL`. This could very well be an sqlite3 database.

```bash
$ mkdir .data
$ DATABASE_URL=sqlite:///../.data/openctf.db python3 -m pytest .
```

Contact
-------

Authors: Michael Zhang, David Hou, James Wang

Copyright: EasyCTF Team

License: TBD

Email: team@easyctf.com
