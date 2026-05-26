{{- define "mcp-janus.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "mcp-janus.fullname" -}}
{{- $name := .Chart.Name }}
{{- if .Release.Name | eq $name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "mcp-janus.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "mcp-janus.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "mcp-janus.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mcp-janus.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
