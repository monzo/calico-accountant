package metrics

import (
	"fmt"
	"net/http"

	"github.com/golang/glog"
	"github.com/monzo/calico-accountant/iptables"
	"github.com/monzo/calico-accountant/watch"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var dropDesc = prometheus.NewDesc("no_policy_drop_counter", "Number of packets dropped to/from a workload because no policies matched them", []string{
	"pod",
	"pod_namespace",
	"app",
	"ip",
	"type",
}, nil)
var acceptDesc = prometheus.NewDesc("policy_accept_counter", "Number of packets accepted by a policy on a workload", []string{
	"pod",
	"pod_namespace",
	"app",
	"ip",
	"type",
	"policy",
}, nil)

var droppedScrapeCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "calico_accountant_dropped_scrape",
	Help: "Number of scrapes that were ignored because all counter values were below a minimum",
})

type Collector struct {
	cw watch.CalicoWatcher

	// If all scrapes are below this value, drop the scrape
	minCounter int
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- acceptDesc
	ch <- dropDesc
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	results, err := iptables.Scan(c.cw)
	if err != nil {
		glog.Errorf("Error scanning for metrics: %v", err)
		return
	}

	// There's seemingly an iptables bug where occasionally all counters drop to 0 or near 0, but only for a split second,
	// and then they jump back up. This really upsets prometheus, so we should drop scrapes when everything is small.
	var scrapeAllowed bool
	for _, result := range results {
		if result.PacketCount >= c.minCounter {
			scrapeAllowed = true
			break
		}
	}

	if !scrapeAllowed {
		glog.Warningf("Dropping scrape; all %d counters are below minimum count of %d", len(results), c.minCounter)

		droppedScrapeCounter.Inc()
		return
	}

	for _, result := range results {
		err := parse(ch, result, c.cw)
		if err != nil {
			glog.Errorf("Cannot parse the result: %+v, error: %v", result, err)
		}
	}
}

func parse(metricChan chan<- prometheus.Metric, r *iptables.Result, cw watch.CalicoWatcher) error {
	switch r.CountType {
	case iptables.Drop:
		metricChan <- prometheus.MustNewConstMetric(
			dropDesc,
			prometheus.CounterValue,
			float64(r.PacketCount),
			r.PodName,
			r.PodNamespace,
			r.AppLabel,
			r.PodIP,
			r.ChainType.String(),
		)
	case iptables.Accept:
		policyName := cw.GetPolicyByChainName(r.Target)

		metricChan <- prometheus.MustNewConstMetric(
			acceptDesc,
			prometheus.CounterValue,
			float64(r.PacketCount),
			r.PodName,
			r.PodNamespace,
			r.AppLabel,
			r.PodIP,
			r.ChainType.String(),
			policyName,
		)
	}

	return nil
}

func Run(cw watch.CalicoWatcher, port string, minCounter int) {
	r := prometheus.NewRegistry()

	c := &Collector{
		cw:         cw,
		minCounter: minCounter,
	}

	r.MustRegister(c)
	r.MustRegister(droppedScrapeCounter)

	handler := promhttp.HandlerFor(r, promhttp.HandlerOpts{})

	http.Handle("/metrics", handler)
	err := http.ListenAndServe(fmt.Sprintf(":%v", port), nil)
	if err != nil {
		glog.Fatal(err) // exit the program if it fails to serve metrics
	}
}
