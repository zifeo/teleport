package metrics

import (
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws/middleware/private/metrics"
	"github.com/aws/aws-sdk-go-v2/aws/middleware/private/metrics/middleware"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/gravitational/teleport"
)

var (
	labels        = []string{"service", "action", "code"}
	TotalRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: teleport.MetricNamespace,
		Name:      "aws_sdk_go_request_total",
		Help:      "The total number of AWS SDK Go requests",
	}, labels)

	TotalRequestAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: teleport.MetricNamespace,
		Name:      "aws_sdk_go_request_attempt_total",
		Help:      "The total number of AWS SDK Go request attempts",
	}, labels)

	RequestLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: teleport.MetricNamespace,
		Name:      "aws_sdk_go_request_duration_seconds",
		Help:      "Latency of AWS SDK Go requests",
		Buckets:   prometheus.ExponentialBuckets(0.001, 2, 10),
	}, labels)

	RequestAttemptLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: teleport.MetricNamespace,
		Name:      "aws_sdk_go_request_attempt_duration_seconds",
		Help:      "Latency of AWS SDK Go request attempts",
		Buckets:   prometheus.ExponentialBuckets(0.001, 2, 10),
	}, labels)

	RetryCount = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: teleport.MetricNamespace,
		Name:      "aws_sdk_go_request_retry_count",
		Help:      "The total number of AWS SDK Go retry attempts per request",
		Buckets: []float64{
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		},
	}, labels)
)

func init() {
	RegisterPrometheusCollectors(TotalRequests, TotalRequestAttempts, RequestLatency, RequestAttemptLatency, RetryCount)
}

// AWSPrometheusMiddleware creates a middleware that auto instruments aws requests with
// prometheus metrics.
func AWSPrometheusMiddleware() func(*smithymiddleware.Stack) error {
	return func(s *smithymiddleware.Stack) error {
		return middleware.WithMetricMiddlewares(prometheusPublisher{}, http.DefaultClient)(s)
	}
}

func requestLabels(service string, action string, statusCode int) prometheus.Labels {
	return prometheus.Labels{
		"service": service,
		"action":  action,
		"code":    fmt.Sprint(statusCode),
	}
}

type prometheusPublisher struct{}

// PostRequestMetrics publishes request metrics to the prometheus registry.
func (p prometheusPublisher) PostRequestMetrics(data *metrics.MetricData) error {
	TotalRequests.With(requestLabels(data.ServiceID, data.OperationName, data.StatusCode)).Inc()
	RequestLatency.With(requestLabels(data.ServiceID, data.OperationName, data.StatusCode)).Observe(float64(data.APICallDuration.Milliseconds()))
	RetryCount.With(requestLabels(data.ServiceID, data.OperationName, data.StatusCode)).Observe(float64(data.RetryCount))

	for _, attempt := range data.Attempts {
		TotalRequestAttempts.With(requestLabels(data.ServiceID, data.OperationName, attempt.StatusCode)).Inc()
		RequestAttemptLatency.With(requestLabels(data.ServiceID, data.OperationName, data.StatusCode)).Observe(float64(attempt.ServiceCallDuration))
	}
	return nil
}

// PostStreamMetrics publishes the stream metrics to the prometheus registry.
func (p prometheusPublisher) PostStreamMetrics(data *metrics.MetricData) error {
	TotalRequests.With(requestLabels(data.ServiceID, data.OperationName, data.StatusCode)).Inc()
	return nil
}
