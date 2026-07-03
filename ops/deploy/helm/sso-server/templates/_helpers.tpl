{{- /*
sso-server Helm chart helpers.

Usage:
  {{ include "sso-server.name" . }}
  {{ include "sso-server.fullname" . }}
  {{ include "sso-server.namespace" . }}
*/}}

{{- define "sso-server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sso-server.fullname" -}}
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

{{- define "sso-server.namespace" -}}
{{- if .Values.global.namespaceOverride }}
{{- .Values.global.namespaceOverride }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}

{{- define "sso-server.labels" -}}
helm.sh/chart: {{ include "sso-server.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "sso-server.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: snaplink-sso
{{- end }}

{{- define "sso-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sso-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
