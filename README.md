# scc-analyzer

[![goreportcard](https://goreportcard.com/badge/github.com/michaelkotelnikov/scc-analyzer)](https://goreportcard.com/report/github.com/michaelkotelnikov/scc-analyzer)

```
$ scc-analyzer --namespace prometheus-michael --expand
+--------------------+-----------------+--------------------------------+------------+
|     NAMESPACE      | SERVICE ACCOUNT |        RULE DESCRIPTION        |    SCC     |
+--------------------+-----------------+--------------------------------+------------+
| prometheus-michael | default         | runAsUser.type: RunAsAny       | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | seLinuxContext.type: RunAsAny  | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowHostNetwork: true         | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowHostPorts: true           | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowPrivilegeEscalation: true | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | fsGroup.type: RunAsAny         | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowHostIPC: true             | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowPrivilegedContainer: true | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowHostDirVolumePlugin: true | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowHostPID: true             | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | volumes: [*]                   | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowedCapabilities: [*]       | privileged |
+                    +-----------------+--------------------------------+------------+
|                    | michael         | allowHostNetwork: true         | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowPrivilegedContainer: true | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowHostDirVolumePlugin: true | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowHostPorts: true           | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowPrivilegeEscalation: true | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | runAsUser.type: RunAsAny       | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | seLinuxContext.type: RunAsAny  | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | fsGroup.type: RunAsAny         | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowedCapabilities: [*]       | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowHostIPC: true             | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowHostPID: true             | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | volumes: [*]                   | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | runAsUser.type:                | nonroot    |
|                    |                 | MustRunAsNonRoot               |            |
+                    +                 +--------------------------------+------------+
|                    |                 | fsGroup.type: RunAsAny         | nonroot    |
+                    +                 +--------------------------------+------------+
|                    |                 | allowPrivilegeEscalation: true | nonroot    |
+                    +-----------------+--------------------------------+------------+
|                    | prometheus      | runAsUser.type: RunAsAny       | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowHostIPC: true             | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowHostNetwork: true         | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowPrivilegedContainer: true | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowHostDirVolumePlugin: true | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowHostPID: true             | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | seLinuxContext.type: RunAsAny  | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | fsGroup.type: RunAsAny         | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowHostPorts: true           | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowPrivilegeEscalation: true | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | volumes: [*]                   | privileged |
+                    +                 +--------------------------------+------------+
|                    |                 | allowedCapabilities: [*]       | privileged |
+--------------------+-----------------+--------------------------------+------------+
```
