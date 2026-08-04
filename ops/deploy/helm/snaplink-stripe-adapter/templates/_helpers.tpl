{{- define "snaplink-stripe-adapter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "snaplink-stripe-adapter.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "snaplink-stripe-adapter.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "snaplink-stripe-adapter.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "snaplink-stripe-adapter.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: snaplink-sso
{{- end }}

{{- define "snaplink-stripe-adapter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "snaplink-stripe-adapter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "snaplink-stripe-adapter.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "snaplink-stripe-adapter.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when create=false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "snaplink-stripe-adapter.image" -}}
{{- if .image.digest }}{{ .image.repository }}@{{ .image.digest }}{{- else }}{{ .image.repository }}:{{ .image.tag }}{{- end }}
{{- end }}
