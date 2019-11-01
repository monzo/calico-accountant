package main

import (
	"flag"
	"os"
	"strconv"

	"github.com/golang/glog"
	"github.com/monzo/calico-accountant/metrics"
	"github.com/monzo/calico-accountant/watch"
)

func main() {
	flag.Parse()

	port, ok := os.LookupEnv("METRICS_SERVER_PORT")
	if !ok {
		port = "9009"
	}

	var minCounter int
	minCounterStr, ok := os.LookupEnv("MINIMUM_COUNTER")
	if ok {
		var err error
		minCounter, err = strconv.Atoi(minCounterStr)
		if err != nil {
			glog.Fatalf("Failed to parse minimum counter: %v", err)
		}
	}

	cw, err := watch.New()
	if err != nil {
		glog.Fatalf("Error setting up calico watcher: %v", err)
	}

	metrics.Run(cw, port, minCounter)
}
