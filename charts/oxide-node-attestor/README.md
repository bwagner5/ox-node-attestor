# oxide-node-attestor

![Version: 0.0.1](https://img.shields.io/badge/Version-0.0.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.0.1](https://img.shields.io/badge/AppVersion-0.0.1-informational?style=flat-square)

A Helm chart for the Oxide node attestor, which admits Oxide instances to a Kubernetes cluster by attestation.

**Homepage:** <https://github.com/oxidecomputer/oxide-node-attestor>

## Installing the Chart

```console
helm upgrade --install oxide-node-attestor oci://ghcr.io/oxidecomputer/helm-charts/oxide-node-attestor \
  --namespace kube-system \
  --set settings.oxide.host=${OXIDE_HOST} \
  --set settings.oxide.project=${OXIDE_PROJECT} \
  --set-file settings.platformRoots=platform-roots.pem
```

The Oxide API token (`settings.oxide.tokenSecret`) and the serving certificate
(`settings.tls.secretName`) are read from Secrets in the release namespace, which this
chart does not create.

## Source Code

* <https://github.com/oxidecomputer/oxide-node-attestor>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| additionalAnnotations | object | `{}` | Additional annotations to add into metadata. |
| additionalLabels | object | `{}` | Additional labels to add into metadata. |
| affinity | object | `{}` | Affinity rules for scheduling the pod. |
| env | list | `[]` | Additional environment variables for the attestor pod. |
| fullnameOverride | string | `""` | Overrides the chart's computed fullname. |
| image.digest | string | `""` | SHA256 digest of the attestor image. |
| image.repository | string | `"ghcr.io/oxidecomputer/oxide-node-attestor"` | Repository path to the attestor image. |
| image.tag | string | `""` | Tag of the attestor image. |
| imagePullPolicy | string | `"IfNotPresent"` | Image pull policy for Docker images. |
| imagePullSecrets | list | `[]` | Image pull secrets for Docker images. |
| kubeconfig.secretName | string | `""` | Secret holding a kubeconfig (key `value`) for the cluster nodes join, when the attestor runs outside it. Its user needs what `rbac.create` would grant. |
| nameOverride | string | `""` | Overrides the chart's name. |
| nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node selectors to schedule the pod to nodes with labels. |
| podAnnotations | object | `{}` | Additional annotations for the pod. |
| podLabels | object | `{}` | Additional labels for the pod. |
| podSecurityContext | object | `{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}}` | SecurityContext for the pod. |
| port | int | `8443` | The container port the attestor serves on. |
| priorityClassName | string | `"system-cluster-critical"` | PriorityClass name for the pod. |
| rbac.create | bool | `true` | Specifies if the ServiceAccount's roles and bindings should be created. |
| replicas | int | `1` | Number of replicas. More than one needs `settings.nonceKeySecret`. |
| resources | object | `{}` | Resources for the attestor pod. |
| revisionHistoryLimit | int | `10` | The number of old ReplicaSets to retain to allow rollback. |
| service.annotations | object | `{}` | Additional annotations for the Service. |
| service.port | int | `443` | Port of the Service. |
| service.type | string | `"ClusterIP"` | Type of the Service nodes reach the attestor through. |
| serviceAccount.annotations | object | `{}` | Additional annotations for the ServiceAccount. |
| serviceAccount.create | bool | `true` | Specifies if a ServiceAccount should be created. |
| serviceAccount.name | string | `""` | The name of the ServiceAccount to use. |
| settings | object | `{"certificateTTL":"","issuer":"certificate","nonceKeySecret":{"key":"key","name":""},"oxide":{"host":"","project":"","tokenSecret":{"key":"token","name":"oxide-api-token"}},"platformRoots":"","rateLimit":"","sledSerials":[],"tls":{"secretName":"oxide-node-attestor-tls"},"tokenGroups":[],"tokenTTL":""}` | Settings to configure the attestor. |
| settings.certificateTTL | string | `""` | Lifetime of an issued certificate. Defaults to 10m, the least a cluster signs. |
| settings.issuer | string | `"certificate"` | Credential issued to an admitted node: `certificate`, a short-lived kubelet client certificate, or `token`, a bootstrap token. |
| settings.nonceKeySecret | object | `{"key":"key","name":""}` | Secret holding a key of at least 32 bytes that replicas share to accept each other's nonces. Unset, each replica makes its own. |
| settings.oxide | object | `{"host":"","project":"","tokenSecret":{"key":"token","name":"oxide-api-token"}}` | Oxide API configuration. |
| settings.oxide.host | string | `""` | URL of the Oxide API, for example https://oxide.sys.example.com. |
| settings.oxide.project | string | `""` | Oxide project whose instances may join the cluster. |
| settings.oxide.tokenSecret | object | `{"key":"token","name":"oxide-api-token"}` | Secret in the release namespace holding the Oxide API token, which needs to read the project's instances. |
| settings.platformRoots | string | `""` | PEM platform identity root certificates attestations must chain to. |
| settings.rateLimit | string | `""` | Requests per second served across all callers. Defaults to 20. |
| settings.sledSerials | list | `[]` | Serials of the only sleds attestations may come from. Empty admits any sled under `platformRoots`. |
| settings.tls.secretName | string | `"oxide-node-attestor-tls"` | Secret (keys `tls.crt` and `tls.key`) holding the serving certificate, which nodes must be able to verify. Not created by this chart. |
| settings.tokenGroups | list | `[]` | Extra groups an issued token authenticates into. |
| settings.tokenTTL | string | `""` | Lifetime of an issued token. Defaults to 2m. |
| tolerations | list | `[{"key":"CriticalAddonsOnly","operator":"Exists"}]` | Tolerations to allow the pod to be scheduled to nodes with taints. |

----------------------------------------------

Autogenerated from chart metadata using [helm-docs](https://github.com/norwoodj/helm-docs/).
