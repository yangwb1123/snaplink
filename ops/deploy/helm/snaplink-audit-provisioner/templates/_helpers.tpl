{{- define "snaplink-audit-provisioner.name" -}}
snaplink-audit-provisioner
{{- end }}

{{- define "snaplink-audit-provisioner.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "snaplink-audit-provisioner.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "snaplink-audit-provisioner.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "snaplink-audit-provisioner.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when create=false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end }}

{{- define "snaplink-audit-provisioner.desiredConfigMap" -}}
{{- if .Values.desiredState -}}
{{- include "snaplink-audit-provisioner.fullname" . -}}
{{- else -}}
{{- .Values.config.existingDesiredConfigMap -}}
{{- end -}}
{{- end }}
