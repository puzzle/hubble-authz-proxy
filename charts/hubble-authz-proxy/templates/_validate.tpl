{{/*
Configuration that would deploy something quietly wrong.

Everything here fails the render rather than warning, because each case produces
a deployment that starts cleanly, serves traffic, and is incorrect in a way no
log line reports.
*/}}

{{- define "hubble-authz-proxy.validate" -}}

{{/*
The proxy holds per-client service-map state in memory.

ui.ServiceLink names its endpoints by opaque service ID and carries no
namespace; the only place that mapping appears is the ServiceState event
announcing the service, which may have arrived on an earlier poll. So the proxy
remembers it, keyed by the backend's channel ID — in the memory of the pod that
saw it.

Spread a client's polls across replicas and the pod handling this one has never
seen those announcements. Unknown endpoints are failed closed, correctly, so the
user's service map loses edges at random with nothing logged and no error
anywhere. It looks like Hubble is flaky, not like a misconfiguration.

Session affinity on the Service pins a client to one pod and restores the
invariant. It is required rather than defaulted because affinity alone is not
always enough: an ingress controller that load-balances to pod IPs directly
(Traefik and Cilium's own ingress can, bypassing kube-proxy) needs its own
stickiness configured too, and only you know whether yours does. replicaCount: 1
is the configuration with no such caveat.
*/}}
{{- $replicas := int .Values.replicaCount }}
{{- if gt $replicas 1 }}
  {{- $affinity := "" }}
  {{- if .Values.hubbleUI.enabled }}
    {{- $affinity = .Values.hubbleUI.service.sessionAffinity }}
  {{- else }}
    {{- $affinity = .Values.service.sessionAffinity }}
  {{- end }}
  {{- $key := ternary "hubbleUI.service.sessionAffinity" "service.sessionAffinity" .Values.hubbleUI.enabled }}
  {{- if ne (toString $affinity) "ClientIP" }}
    {{- fail (printf "replicaCount is %d but %s is not \"ClientIP\".\n\nThe proxy keeps per-client service-map state in memory, so a client whose polls land on different replicas loses service-map links with no error reported. Either:\n  - set replicaCount: 1 (no caveats), or\n  - set %s: ClientIP AND confirm your ingress controller is sticky too — one that balances straight to pod IPs bypasses Service affinity entirely." $replicas $key $key) }}
  {{- end }}
{{- end }}

{{- end }}
