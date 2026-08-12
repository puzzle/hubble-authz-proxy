{{- define "hubble-authz-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "hubble-authz-proxy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "hubble-authz-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "hubble-authz-proxy.labels" -}}
helm.sh/chart: {{ include "hubble-authz-proxy.chart" . }}
{{ include "hubble-authz-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "hubble-authz-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "hubble-authz-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "hubble-authz-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "hubble-authz-proxy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "hubble-authz-proxy.backendServiceName" -}}
{{- default (printf "%s-backend" (include "hubble-authz-proxy.fullname" .)) .Values.backend.service.name }}
{{- end }}

{{/*
The URL the proxy dials. An explicit backend.url always wins; otherwise we point
at the Service this chart creates for the hubble-ui backend sidecar.
*/}}
{{- define "hubble-authz-proxy.backendURL" -}}
{{- if .Values.backend.url }}
{{- .Values.backend.url }}
{{- else if .Values.backend.service.create }}
{{- $ns := default .Release.Namespace .Values.backend.service.namespace }}
{{- printf "http://%s.%s.svc.cluster.local:%d" (include "hubble-authz-proxy.backendServiceName" .) $ns (int .Values.backend.service.port) }}
{{- else }}
{{- fail "Set either backend.url or backend.service.create — the proxy has no upstream otherwise." }}
{{- end }}
{{- end }}

{{- define "hubble-authz-proxy.mappingConfigMapName" -}}
{{- default (printf "%s-mapping" (include "hubble-authz-proxy.fullname" .)) .Values.authz.existingConfigMap }}
{{- end }}

{{/* Name of the Hubble UI resources this chart owns in standalone mode. */}}
{{- define "hubble-authz-proxy.uiFullname" -}}
{{- printf "%s-ui" (include "hubble-authz-proxy.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "hubble-authz-proxy.uiSelectorLabels" -}}
app.kubernetes.io/name: {{ include "hubble-authz-proxy.name" . }}-ui
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "hubble-authz-proxy.uiLabels" -}}
helm.sh/chart: {{ include "hubble-authz-proxy.chart" . }}
{{ include "hubble-authz-proxy.uiSelectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
The port the proxy listens on, as a bare number. proxy.listen is a listen
address (":8090"), but nginx and containerPort need the number alone.
*/}}
{{- define "hubble-authz-proxy.listenPort" -}}
{{- $parts := splitList ":" .Values.proxy.listen -}}
{{- $port := last $parts -}}
{{- if not $port }}{{ fail (printf "cannot derive a port from proxy.listen=%q" .Values.proxy.listen) }}{{ end -}}
{{- $port }}
{{- end }}

{{/*
Secret holding oauth2-proxy's credentials. An existingSecret is preferred;
otherwise the chart renders one from values, which means the values land in the
release history too.
*/}}
{{- define "hubble-authz-proxy.oauth2SecretName" -}}
{{- default (printf "%s-oauth2-proxy" (include "hubble-authz-proxy.uiFullname" .)) .Values.hubbleUI.oauth2Proxy.existingSecret }}
{{- end }}
