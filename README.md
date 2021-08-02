# UID2 Core

The UID 2 Project is subject to Tech Lab IPR’s Policy and is managed by the IAB Tech Lab Addressability Working Group and Privacy & Rearc Commit Group. Please review the governance rules [here](https://github.com/IABTechLab/uid2-core/blob/master/Software%20Development%20and%20Release%20Procedures.md)

## Prerequisite

To setup dependencies before building, run the follow script

```bash
./setup_dependencies.sh
```

## Building

To run unit tests:

```
mvn clean test
```

To package application:

```
mvn package
```

To run application:

- for local debugging that loads salt and key stores from mock storage provider, use `config/local-config.json`:

```
mvn clean compile exec:java -Dvertex-configpath=conf/local-config.json
```

- for integration test, you need to prepare config and secrets in `conf/integ-config.json` to run core service that loads salt and key stores from aws s3:
  
```
mvn clean compile exec:java -Dvertx-config-path=conf/integ-config.json
```
