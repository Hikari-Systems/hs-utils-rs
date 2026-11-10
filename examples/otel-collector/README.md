# Per-host OpenTelemetry Collector

`config.yaml` is the reference Collector for a fleet host: services export to it, and it adds host metrics
(including host CPU iowait), per-container stats and EC2 resource attributes, then forwards to Honeycomb.

Run it as one more container on the host:

```sh
docker run -d --name otel-collector --restart unless-stopped \
  --network host \
  -e HONEYCOMB_API_KEY \
  -v /:/hostfs:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/config.yaml:/etc/otelcol-contrib/config.yaml:ro" \
  otel/opentelemetry-collector-contrib:<pinned version>
```

Point each service at it, and stop requiring a key there:

```json
"otel": {
  "enabled": "true",
  "endpoint": "http://127.0.0.1:4318",
  "apiKeyRequired": "false",
  "serviceName": "woodhouse-data-service",
  "environment": "preview"
}
```

From a container on a bridge network rather than the host network, use the host gateway address
(`--add-host=host.docker.internal:host-gateway`, then `http://host.docker.internal:4318`).

Pin the image tag. `docker_stats` and `hostmetrics` are contrib components, so the plain `otel/opentelemetry-collector`
image does not have them.
