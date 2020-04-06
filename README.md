# calico-accountant

calico-accountant is a prometheus exporter that helps you track the consequences of Calico policies. It requests
statistics from iptables on the number of packets accepted by each policy for each workload, and the number of packets 
dropped because no policies matched them.

calico-accountant itself runs as a Pod in your cluster, and needs access only to the Calico datastore. It maintains an
internal cache of workloads on the host on which it runs, as well as a mapping from policy chain names to Calico policy
names.

## Installation

Download the source code package:
```shell
$ git clone github.com/monzo/calico-accountant
```

Build the container from the source code (make sure you have Docker running):
```shell
$ cd $GOPATH/src/github.com/monzo/calico-accountant
$ make container
```

## Usage 

### Examples of use
1. Use calico-accountant to see how many packets are being passed by each of your calico policies, and how many are dropped because no policies passed them.
Alert if there are dropped packets, or if a key policy sees less traffic.
2. Test your policies in a safe way by setting up a high-order allow all policy, then your more restrictive policy (that you hope matches all traffic) on a lower
order. If no packets are allowed by the allow all policy, then your restrictive policy must fully specify all required traffic.

### Privilege
calico-accountant needs root privileges to interact with iptables.

### Container Spec
We suggest running calico-accountant as a [Daemonset](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) in your cluster. An example of YAML spec file can be found in [demo/](demo/).

### Environment Variables 

#### Required: 
You will need to provide the correct environment variables for the Calico datastore client. This may be as simple as
providing `ETCD_ENDPOINTS`. The setup can be copied from the Calico kube-controllers or from Calico node.

#### Optional:
* `NODENAME`: (string, default: hostname, to match calico node behaviour) Should be equal to `spec.nodeName`, ie the Kubernetes node name. 
See the demo manifest for one way to provide this. If you don't provide this to calico node, you may not need to provide it here either.
* `METRICS_SERVER_PORT`: (int, default: **9009**) Port for the service to host its metrics.
* `MINIMUM_COUNTER`: (int, default **0**) Scrapes where all counts are below this value are dropped. This is to dodge iptables race conditions where counters briefly drop to near-zero and then return.

### Metrics 
Metrics are implemented by Prometheus, which are hosted on the web server at `/metrics`. 

Every scrape leads to a single `iptables-save` command.

Exported metrics:
```go
var dropDesc = prometheus.NewDesc("no_policy_drop_counter", "Number of packets dropped to/from a workload because no policies matched them", []string{
	"pod", // the name of the Kubernetes pod, if any
	"app", // the value of the "app" label of the pod, if any
	"ip", // a comma separated list of ips or subnets associated with the workload
	"type", // fw = from workload, tw = to workload
}, nil)
var acceptDesc = prometheus.NewDesc("policy_accept_counter", "Number of packets accepted by a policy on a workload", []string{
	"pod",
	"app",
	"ip",
	"type",
	"policy", // full name of the accepting calico policy, eg default/knp.default.foo
}, nil)
```

## Credits

Inspiration was taken from [kube-iptables-tailer](https://github.com/box/kube-iptables-tailer)
