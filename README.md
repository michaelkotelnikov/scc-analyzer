# scc-analyzer

```
./scc-analyzer --namespace prometheus-michael
+--------------------+-----------------+--------------------------------+------------+
|     NAMESPACE      | SERVICE ACCOUNT |        RULE DESCRIPTION        |    SCC     |
+--------------------+-----------------+--------------------------------+------------+
| prometheus-michael | default         | 'allowHostNetwork: true'       | privileged |
|                    |                 | is set. This setting allows    |            |
|                    |                 | containers to access the       |            |
|                    |                 | underlying host's network      |            |
|                    |                 | namespace.                     |            |
+                    +                 +--------------------------------+------------+
|                    |                 | 'runAsUser.type: RunAsAny'     | privileged |
|                    |                 | is set. This setting allows    |            |
|                    |                 | containers to run as insecure  |            |
|                    |                 | UIDs on the underlying host.   |            |
+                    +                 +--------------------------------+------------+
|                    |                 | 'allowHostIPC: true' is set.   | privileged |
|                    |                 | This setting allows containers |            |
|                    |                 | to access the underlying       |            |
|                    |                 | host's IPC namespace.          |            |
+                    +-----------------+--------------------------------+------------+
|                    | michael         | 'allowHostIPC: true' is set.   | privileged |
|                    |                 | This setting allows containers |            |
|                    |                 | to access the underlying       |            |
|                    |                 | host's IPC namespace.          |            |
+                    +                 +--------------------------------+------------+
|                    |                 | 'allowHostNetwork: true'       | privileged |
|                    |                 | is set. This setting allows    |            |
|                    |                 | containers to access the       |            |
|                    |                 | underlying host's network      |            |
|                    |                 | namespace.                     |            |
+                    +                 +--------------------------------+------------+
|                    |                 | 'runAsUser.type: RunAsAny'     | privileged |
|                    |                 | is set. This setting allows    |            |
|                    |                 | containers to run as insecure  |            |
|                    |                 | UIDs on the underlying host.   |            |
+                    +                 +--------------------------------+------------+
|                    |                 | 'runAsUser.type:               | nonroot    |
|                    |                 | MustRunAsNonRoot' is set. This |            |
|                    |                 | setting allows containers to   |            |
|                    |                 | run as insecure UIDs on the    |            |
|                    |                 | underlying host.               |            |
+                    +-----------------+--------------------------------+------------+
|                    | prometheus      | 'allowHostIPC: true' is set.   | privileged |
|                    |                 | This setting allows containers |            |
|                    |                 | to access the underlying       |            |
|                    |                 | host's IPC namespace.          |            |
```
