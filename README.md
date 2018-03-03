# OAuth2

OAuth2 helps process oauth2 connections

[![Build Status](https://travis-ci.org/build-tanker/oauth2.svg?branch=master)](https://travis-ci.org/build-tanker/oauth2)
[![codecov](https://codecov.io/gh/build-tanker/oauth2/branch/master/graph/badge.svg)](https://codecov.io/gh/build-tanker/oauth2)

## Getting Started

oauth2 gives you functions to run through the complete flow

### Prerequisites

Here are the things that you would require before you get started

1. [Install git](https://www.atlassian.com/git/tutorials/install-git)
1. [Install golang](https://golang.org/doc/install)

### Using Oauth2

You can install it into your project using

```bash
dep ensure -add github.com/build-tanker/oauth2
```

### Installing

Clone the repo and build it

```bash
git clone https://github.com/build-tanker/oauth2.git
make build
```

## Running the tests

If you would like to run the automated tests for the complete package, run this

```bash
make coverage
open ./coverage.html
```

### And coding style tests

We use the default golang coding conventions. Run the following to test for those

```bash
make fmt
make vet
make lint
```

## Contributing

Please read [CONTRIBUTING.md](https://github.com/build-tanker/oauth2/blob/master/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](https://semver.org/spec/v2.0.0.html) for versioning based on the recommendation from [Dave Chaney](https://dave.cheney.net/2016/06/24/gophers-please-tag-your-releases). For the versions available, see the [tags on this repository](https://github.com/build-tanker/oauth2/tags).

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](https://github.com/build-tanker/oauth2/blob/master/LICENSE) file for details