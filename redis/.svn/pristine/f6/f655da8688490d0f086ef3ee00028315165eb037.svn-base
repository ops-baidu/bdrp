# bdrp (baidu redis paltform)

**bdrp** is redis cluster solution based on [twemproxy](https://github.com/twitter/twemproxy) and [redis](http://redis.io/). Bdrp use _nutcracker_, _redis-server_ and _redis-sentinel_ to build a high available cluster with higher data reliability compared to twemproxy's  consistent hashing.

## Build

Bdrp cluster is consist of _nutcracker_, _redis-server_ and _redis-sentinel_.

To build nutcracker consult [nutcracker-0.2.4/README.md](nutcracker-0.2.4/README.md)

To build redis-server and redis-sentinel consult [redis-2.6.16/README](redis-2.6.16/README)

## Features

Bdrp has some new features below compared to twemproxy

+ high availability with higher data reliability
+ Higher performance with read write spliting
+ support client permission authorization with white list

## Configuration

nutcracker, redis-server, redis-sentinel should be configured properly to set up a bdrp cluster with the features mentioned above. Some key configuration items in each component will be described below.

+ **nutcracker**: 
  + auto\_eject\_hosts: It should be configured to false to avoid data loss. Bdrp use redis master slave switch to achieve high availability instead of consistent hashing which will cause data loss.
  + nodes name: Each redis sharding must have nodes name. Because nutcracker will use nodes name to identify which master redis is switched in redis-sentinel's publish message. 
  + mutiple addresses in redis sharding: To enable read write spliting, mutiple addresses should be configured in each redis sharding. The first address should be the master redis in the sharding, it will be forwarded write requests. The others should be the slave redis in the sharding, they will be forwarded read requests round robin. Configuring only one address to disable it.


For example, the nutcracker configuration shown below, server pool sigma configures auto\_eject\_hosts to false. And it has two redis shardings(server1 and server2). Each sharding has one master and two slave.

    sigma:
      listen: 127.0.0.1:22125
      hash: crc16
      distribution: slot
      preconnect: true
      auto_eject_hosts: false
      redis: true
      backlog: 512
      client_connections: 0
      server_connections: 1
      server_retry_timeout: 2000
      server_failure_limit: 2
      servers:
       - server1
         127.0.0.1:6379:1
         127.0.0.1:6380:1
         127.0.0.1:6381:1
       - server2
         127.0.0.1:7379:1
         127.0.0.1:7380:1
         127.0.0.1:7381:1

+ **redis-sentinel**: 
  + master-name: It should be configured to the format like "poolname-nodesname". Nutcracker will parse out the pool name and nodes name in publish message, then modify its forward address.
  + can-failover: It should be configured to yes. Then the redis-sentinel can do failover when the master is down.

For example, the redis-sentinel configuration shown below. It corresponds to the nutcracker configuration shown above. Master names are configured to sigma-server1 and sigma-server2. Can-failover is configured to yes.

    sentinel monitor sigma-server1 127.0.0.1 6379 2
    sentinel down-after-milliseconds sigma-server1 10000 
    sentinel can-failover sigma-server1 yes
    sentinel parallel-syncs sigma-server1 1
    sentinel failover-timeout sigma-server1 90000

    sentinel monitor sigma-server2 127.0.0.1 7379 2
    sentinel down-after-milliseconds sigma-server2 10000 
    sentinel can-failover sigma-server2 yes
    sentinel parallel-syncs sigma-server2 1
    sentinel failover-timeout sigma-server2 90000

+ **redis-server**: There is no configuration should be payed special attention to in bdrp. 


## Issues and Support

Have a bug or a question? Please create an issue here on GitHub!

https://github.com/ops-baidu/bdrp/issues

## Contributors

* Qi Zebin ([@andyqzb](http://weibo.com/andyqzb))

## License

Copyright 2014 Baidu, Inc.

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
