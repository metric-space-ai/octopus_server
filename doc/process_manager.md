Process manager
===============

There are two main ways we can implement a process manager for octopus_server:
* Use Kubernetes, Docker, Docker-Compose, or any other cluster management solution
* Implement own simple process management on top of Linux control groups infrastructure (cgroups are used by above cluster management solutions)

First way
---------

By using Kubernetes, Docker, Docker-Compose we leverage existing, proven solutions, but we also may encounter problems that can be only resolved on the cluster management solution level.

There are two ways we can attack the problem:
* Trying to manage from octopus_server container level
* Trying to manage from cluster level

The first solution may be risky because in case of some logic error on octopus_server level code or in configuration, we risk a situation when cluster management software kills a container with octopus_server.

The second solution is not risky but is more problematic. It requires having an instance of octopus_server in process management mode on the same level as we have i.e. K8s. Because of that, we may need to use another solution like docker-compose to manage just this one instance.

It will also require us to build two sets of images of octopus_server. One for normal operations mode, and another one for process management mode.

In both cases, we can try to find a library that would help us with communication with the cluster software like https://crates.io/crates/k8s-openapi

Direct access to the cluster state will be only possible while using the first solution. For the second solution octopus_server in process, manager mode will have to save information about the cluster state in the database.

Generally second solution will be more complicated also because whole octopus_server in API mode and octopus_server in process manager mode communication will go through database statuses and queues.

In this way we will have to use an OCI images.

octopus_server will have to generate an OCI image for an AI function and would have to push it to a local repository. Next octopus_server will have to generate a configuration for cluster management solution that will use generated image and run it on the cluster.

Whole life cycle of the container will be handled by cluster managemnt solution. octopus_server will depend on it.

Second way
----------

We can leverage mechanics of the Linux control groups https://en.wikipedia.org/wiki/Cgroups to build own process manager. It will be much simpler solution than other cluster management software.

Everything would work inside one octopus_server container. We would create a separate volume for data directory where functions would be stored.

For isolation purposes we would depend on cgroups. We would not have to track pids, killing service would be handled on cgroup level.

For this way we would have to implement own process spawning, cgroup management and lifecycle handling, logging.

We can try to use some existing solutions like https://docs.rs/steward/latest/steward/ after checking if they work ok with cgroups.

Requirements
------------

Process managment needs to handle:
* AI function process creation
* AI function process observation (logs and status?)
* AI function process killing
* AI function process isolation

Other tings
-----------

Way 1-1 is more easy to implement than Way 1-2, but in case of some error in configuration can lead to disaster when octopus_server container is killed/removed from cluster etc.

Way 1-2 is most harder to implement and challanging, because communication between octopus_server instance that serves API and octopus_server instance that manages processes. But it's most realiable way.

Way 2 is easier to implement than Way 1, but because we would not leverage existing software it may not be as realiable as Way 1 solutions. On the other hand it's most flexible way.
