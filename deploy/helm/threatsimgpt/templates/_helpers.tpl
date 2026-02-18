{{- define "threatsimgpt.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "threatsimgpt.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "threatsimgpt.labels" -}}
app.kubernetes.io/name: {{ include "threatsimgpt.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
