{{- define "snaplink-billing.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "snaplink-billing.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "snaplink-billing.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "snaplink-billing.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "snaplink-billing.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: snaplink-sso
{{- end }}

{{- define "snaplink-billing.selectorLabels" -}}
app.kubernetes.io/name: {{ include "snaplink-billing.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "snaplink-billing.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "snaplink-billing.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when create=false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "snaplink-billing.image" -}}
{{- if .image.digest }}{{ .image.repository }}@{{ .image.digest }}{{- else }}{{ .image.repository }}:{{ .image.tag }}{{- end }}
{{- end }}
