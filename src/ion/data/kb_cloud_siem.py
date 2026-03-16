"""Built-in KB data: Cloud Security, SIEM & Governance."""

CLOUD_SECURITY = [
    {
        "title": "The Shared Responsibility Model",
        "tags": ["cloud", "shared-responsibility", "aws", "azure", "gcp"],
        "content": r"""# The Shared Responsibility Model

The shared responsibility model is the foundational concept that defines who is accountable for what in any cloud deployment. Misunderstanding this boundary is the single most common root cause of cloud security incidents.

## The Core Principle

Cloud providers secure the infrastructure **of** the cloud. Customers secure what they put **in** the cloud. The dividing line shifts depending on the service model.

## Responsibility by Service Model

| Layer | IaaS | PaaS | SaaS |
|---|---|---|---|
| Physical security | Provider | Provider | Provider |
| Network infrastructure | Provider | Provider | Provider |
| Hypervisor / host OS | Provider | Provider | Provider |
| Guest OS / runtime | **Customer** | Provider | Provider |
| Application code | **Customer** | **Customer** | Provider |
| Identity & access | **Customer** | **Customer** | **Customer** |
| Data classification | **Customer** | **Customer** | **Customer** |
| Encryption choices | **Customer** | **Customer** | Shared |
| Network controls (VPC/NSG) | **Customer** | Shared | Provider |

## Provider-Specific Nuances

**AWS** documents the model as "Security of the Cloud vs. Security in the Cloud." AWS manages hardware, global infrastructure, and managed service internals. Customers own IAM policies, S3 bucket policies, security group rules, and encryption key management.

**Azure** uses a similar framework but emphasizes that identity is always a customer responsibility regardless of service tier. Azure AD (Entra ID) configuration, Conditional Access policies, and MFA enforcement are never Microsoft's job.

**GCP** frames it as a "shared fate" model, providing opinionated security defaults (e.g., encryption at rest is automatic, VPC firewall denies all ingress by default) to reduce the customer's burden.

## Common Misconfigurations from Misunderstanding

- Assuming the provider encrypts data in transit between microservices (they often do not inside a VPC)
- Leaving S3 buckets or Azure Blob containers publicly accessible because "the cloud is secure"
- Not patching guest operating systems on EC2/VM instances
- Failing to enable logging (CloudTrail, Azure Activity Log) because "the provider handles that"
- Expecting the provider to detect compromised IAM credentials

## SOC Relevance

Analysts triaging cloud alerts must understand which layer is involved. A misconfigured security group is a customer-side issue; a hypervisor vulnerability is the provider's. This distinction drives escalation paths, remediation ownership, and whether a vendor support ticket is appropriate.

## Key Takeaway

When in doubt, ask: "Who configured this? Who can change it?" If the answer is your organization, security is your responsibility.
""",
    },
    {
        "title": "IAM Best Practices for Cloud Environments",
        "tags": ["cloud", "iam", "least-privilege", "aws", "azure", "gcp"],
        "content": r"""# IAM Best Practices for Cloud Environments

Identity and Access Management (IAM) is the single most critical control plane in any cloud environment. Compromised credentials or overly permissive policies are the leading cause of cloud breaches.

## Principle of Least Privilege

Grant only the minimum permissions required to perform a task. This applies to human users, service accounts, and machine roles alike.

**Implementation pattern:**
1. Start with zero permissions
2. Add specific actions on specific resources
3. Scope to conditions (IP range, time, MFA requirement)
4. Review and prune quarterly

## Root / Global Admin Accounts

- Never use the AWS root account or Azure Global Administrator for daily operations
- Enable MFA (hardware token preferred) on all privileged accounts
- Create a break-glass procedure for emergency root access with dual-custody controls
- Monitor root account usage with alerts (CloudTrail event `ConsoleLogin` with `userIdentity.type = Root`)

## Service Accounts and Machine Identities

- Prefer instance roles (AWS), managed identities (Azure), or workload identity (GCP) over long-lived access keys
- If static credentials are unavoidable, rotate them automatically on a 90-day (or shorter) cycle
- Never embed credentials in source code, container images, or CI/CD pipeline definitions
- Use secrets managers (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)

## Policy Design Patterns

**AWS IAM:**
```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::my-bucket/reports/*",
  "Condition": {
    "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
    "Bool": {"aws:MultiFactorAuthPresent": "true"}
  }
}
```

**Azure RBAC:** Prefer built-in roles over custom. Use PIM (Privileged Identity Management) for just-in-time elevation with approval workflows and time-bound activation.

**GCP:** Use IAM Conditions to restrict bindings by resource name, request time, or destination IP.

## Guardrails and Governance

- **SCPs (AWS):** Service Control Policies at the Organization/OU level prevent even admin users from performing dangerous actions (e.g., disabling CloudTrail)
- **Azure Policy:** Enforce tagging, allowed regions, required encryption at the subscription or management group level
- **GCP Org Policies:** Restrict external sharing, enforce uniform bucket-level access

## Monitoring and Detection

- Alert on IAM policy changes, new access key creation, and privilege escalation paths
- Use tools like AWS Access Analyzer, Azure AD Access Reviews, and GCP IAM Recommender to find unused permissions
- Track `AssumeRole` calls and cross-account access patterns

## SOC Relevance

IAM-related alerts are high-priority because a compromised identity can laterally move across an entire cloud estate within minutes. Analysts should immediately check: What permissions does this identity have? What has it accessed recently? Are there impossible-travel indicators?
""",
    },
    {
        "title": "Cloud Storage Security",
        "tags": ["cloud", "storage", "s3", "blob", "encryption", "data-protection"],
        "content": r"""# Cloud Storage Security

Cloud object storage (AWS S3, Azure Blob Storage, GCP Cloud Storage) is the most commonly misconfigured service in cloud environments. Data exposure incidents from public buckets have affected organizations of every size.

## Access Control Layers

Cloud storage has multiple overlapping access control mechanisms that must all be configured correctly:

**AWS S3:**
1. **Bucket policies** — JSON resource-based policies attached to the bucket
2. **IAM policies** — Identity-based policies attached to users/roles
3. **ACLs** — Legacy per-object access controls (disable these; use bucket policies instead)
4. **Block Public Access** — Account-level and bucket-level kill switch for public access
5. **Access Points** — Named network endpoints with dedicated access policies

**Azure Blob:**
1. **Azure RBAC** — Role assignments at storage account, container, or blob level
2. **SAS tokens** — Time-limited, scoped access URLs
3. **Access keys** — Full-control keys (treat as root credentials)
4. **Public access level** — Container-level setting: private, blob, or container

**GCP Cloud Storage:**
1. **IAM** — Project or bucket-level role bindings
2. **Uniform bucket-level access** — Recommended; disables ACLs
3. **Signed URLs** — Temporary access tokens for specific objects

## Encryption

| Type | AWS | Azure | GCP |
|---|---|---|---|
| At rest (default) | SSE-S3 (AES-256) | Microsoft-managed keys | Google-managed keys |
| Customer-managed key | SSE-KMS | CMK via Key Vault | CMEK via Cloud KMS |
| Client-side | SDK encryption | Client library encryption | SDK encryption |

Always enable encryption at rest. For regulated data, use customer-managed keys to maintain control over key lifecycle and revocation.

## Data Lifecycle and Classification

- Tag objects with classification labels (public, internal, confidential, restricted)
- Enable versioning to protect against accidental deletion and ransomware
- Configure lifecycle policies to transition old data to cheaper tiers or delete it
- Enable soft delete / object lock for critical data to prevent permanent deletion

## Logging and Monitoring

- **S3:** Enable Server Access Logging and CloudTrail data events for sensitive buckets
- **Azure:** Enable Storage Analytics logging and Azure Monitor
- **GCP:** Enable Cloud Audit Logs for data access

Alert on: bucket policy changes, public access modifications, large downloads, access from unusual IP ranges, and cross-account access.

## Common Misconfigurations

- Public read access enabled on sensitive buckets
- Wildcard (`*`) principals in bucket policies
- SAS tokens with overly broad permissions or no expiration
- No encryption on data at rest when compliance requires it
- Missing access logging on buckets containing PII or financial data

## SOC Relevance

Storage exposure alerts are time-critical. A public bucket can be discovered by automated scanners within hours. The immediate response should include: verify the exposure, assess data sensitivity, restrict access, determine if data was accessed, and initiate incident response if PII is involved.
""",
    },
    {
        "title": "VPC Architecture and Network Controls",
        "tags": ["cloud", "vpc", "networking", "security-groups", "nacl", "firewall"],
        "content": r"""# VPC Architecture and Network Controls

Virtual Private Clouds (VPCs) are the network isolation boundary in cloud environments. Proper VPC design is foundational to defense in depth — it limits blast radius, enforces segmentation, and controls traffic flow.

## VPC Design Principles

**Multi-tier architecture:**
- **Public subnets:** Only for resources that must accept inbound internet traffic (load balancers, bastion hosts)
- **Private subnets:** Application servers, databases, internal services — no direct internet access
- **Isolated subnets:** Highly sensitive workloads with no internet connectivity at all

**Multi-AZ deployment:** Spread subnets across availability zones for resilience. Each AZ should mirror the tier structure.

## Security Groups vs. NACLs (AWS)

| Feature | Security Groups | NACLs |
|---|---|---|
| Scope | Instance / ENI level | Subnet level |
| State | Stateful (return traffic auto-allowed) | Stateless (must allow both directions) |
| Rules | Allow only | Allow and deny |
| Evaluation | All rules evaluated | Rules processed in order |
| Default | Deny all inbound, allow all outbound | Allow all |
| Best for | Application-level controls | Subnet-level guardrails |

**Best practice:** Use security groups as the primary control. Use NACLs as a safety net to block known-bad IPs or restrict entire subnets.

## Azure Network Security Groups (NSGs)

- Apply at the subnet or NIC level
- Rules include priority (100-4096), direction, source/destination, port, and action
- Use Application Security Groups (ASGs) to group VMs logically instead of managing IP-based rules
- **Azure Firewall** or third-party NVAs provide L7 inspection for outbound traffic filtering

## GCP Firewall Rules

- VPC-level firewall rules (not subnet-level)
- Use network tags or service accounts as targets
- Default: deny all ingress, allow all egress
- **Hierarchical firewall policies** let organization admins enforce rules across all projects

## Egress Controls

Controlling outbound traffic is as important as inbound:

- **NAT Gateway:** Allow private subnet instances to reach the internet without exposing them to inbound connections
- **Proxy / Forward proxy:** Inspect and filter outbound HTTP/HTTPS traffic
- **VPC Endpoints / Private Link:** Access cloud services (S3, Azure SQL, GCP APIs) without traversing the internet
- **DNS filtering:** Block resolution of known-malicious domains at the VPC resolver level

## Network Flow Logging

- **AWS VPC Flow Logs:** Capture accept/reject decisions for every network interface
- **Azure NSG Flow Logs:** Log traffic processed by NSGs, integrates with Traffic Analytics
- **GCP VPC Flow Logs:** Sample-based packet metadata logging

These logs are essential for threat hunting, incident investigation, and anomaly detection.

## Peering and Transit

- **VPC Peering:** Non-transitive, 1:1 connectivity between VPCs
- **Transit Gateway (AWS) / Virtual WAN (Azure) / Cloud Interconnect (GCP):** Hub-and-spoke topology for connecting many VPCs and on-premises networks
- Apply security groups and NACLs at peering boundaries to prevent unintended cross-VPC access

## SOC Relevance

VPC flow logs are a critical data source for detecting lateral movement, data exfiltration, and unauthorized network access. Analysts should look for traffic to unexpected ports, large data transfers to external IPs, and connections between tiers that should not communicate directly.
""",
    },
    {
        "title": "Cloud Logging — CloudTrail, Azure Monitor, and GCP Audit Logs",
        "tags": ["cloud", "logging", "cloudtrail", "azure-monitor", "audit-logs", "detection"],
        "content": r"""# Cloud Logging — CloudTrail, Azure Monitor, and GCP Audit Logs

Cloud audit logs are the primary evidence source for detecting threats, investigating incidents, and proving compliance in cloud environments. Without proper logging, security teams are blind.

## AWS CloudTrail

CloudTrail records API calls made against your AWS account. Every action — whether from the console, CLI, SDK, or another AWS service — generates an event.

**Key configuration:**
- Create an **organization trail** that covers all accounts and regions
- Enable **management events** (control plane operations) — these are on by default
- Enable **data events** for sensitive resources (S3 object access, Lambda invocations)
- Send logs to a centralized S3 bucket with integrity validation enabled
- Enable **CloudTrail Lake** for SQL-based querying of historical events

**Critical events to monitor:**
- `ConsoleLogin` — especially without MFA or from unusual locations
- `CreateAccessKey`, `CreateUser` — credential creation
- `PutBucketPolicy`, `PutBucketPublicAccessBlock` — storage exposure
- `StopLogging`, `DeleteTrail` — attacker covering tracks
- `AssumeRole` — cross-account or privilege escalation activity
- `AuthorizeSecurityGroupIngress` — firewall rule changes

## Azure Monitor and Activity Log

Azure splits logging into several categories:

**Azure Activity Log:** Platform-level events (resource creation, deletion, policy changes). Equivalent to CloudTrail management events. Retained for 90 days by default; route to a Log Analytics workspace for longer retention.

**Azure AD (Entra ID) Sign-in and Audit Logs:** Authentication events, MFA challenges, Conditional Access evaluations, directory changes. Essential for identity threat detection.

**Diagnostic Settings:** Per-resource logging for data plane events (Key Vault access, SQL query auditing, Storage account operations). Must be explicitly enabled for each resource.

**Key events to monitor:**
- Risky sign-ins and impossible travel detections (Azure AD Identity Protection)
- PIM role activations and approval events
- NSG rule modifications
- Key Vault secret access by unexpected principals

## GCP Cloud Audit Logs

GCP provides four types of audit logs:

1. **Admin Activity** — Always on, no charge. Records resource configuration changes.
2. **Data Access** — Must be enabled per service. Records data reads/writes. Can be high-volume and costly.
3. **System Event** — Google-initiated actions (live migration, automated scaling).
4. **Policy Denied** — Records access attempts denied by VPC Service Controls or Organization Policy.

**Key events to monitor:**
- `SetIamPolicy` — permission changes
- `google.login.LoginService.loginSuccess` — workspace authentication
- Service account key creation
- VPC firewall rule modifications

## Log Centralization and SIEM Integration

Regardless of cloud provider, forward logs to a centralized SIEM for correlation:

- **AWS:** CloudTrail → S3 → SIEM (via SQS notification or direct ingestion)
- **Azure:** Diagnostic Settings → Event Hub → SIEM
- **GCP:** Audit Logs → Pub/Sub → SIEM or export to BigQuery

## Log Integrity and Tamper Protection

- Enable CloudTrail log file integrity validation (digest files with SHA-256 hashes)
- Use immutable storage (S3 Object Lock, Azure Immutable Blob) for audit logs
- Restrict log deletion permissions to a minimal set of break-glass accounts
- Alert immediately on any attempt to disable or modify logging configuration

## SOC Relevance

Cloud logs are typically the only evidence available during an incident — there is no host to image, no packet capture from the hypervisor. Analysts must be proficient in querying CloudTrail, Activity Logs, and Cloud Audit Logs. The first action in any cloud incident is to verify that logging was active and intact during the event window.
""",
    },
    {
        "title": "Container Security — Docker and Kubernetes",
        "tags": ["cloud", "containers", "docker", "kubernetes", "k8s", "security"],
        "content": r"""# Container Security — Docker and Kubernetes

Containers introduce a new attack surface distinct from traditional infrastructure. Security must address the image supply chain, runtime isolation, orchestrator configuration, and workload-to-workload communication.

## Image Security

The container image is the foundation. A vulnerable or malicious image undermines every other control.

**Best practices:**
- Use minimal base images (distroless, Alpine, scratch) — fewer packages means fewer vulnerabilities
- Pin image versions by digest (`sha256:abc123...`), never use `latest` in production
- Scan images in the CI/CD pipeline with tools like Trivy, Grype, or Snyk Container
- Sign images with cosign or Docker Content Trust and enforce signature verification at deployment
- Maintain a private registry with vulnerability scanning enabled (ECR, ACR, Artifact Registry, Harbor)

**Common image risks:**
- Running as root inside the container
- Including build tools, shells, or package managers in production images
- Embedding secrets (API keys, certificates) in image layers — they persist even if deleted in later layers

## Docker Runtime Security

- Run containers as non-root users (`USER 1000` in Dockerfile)
- Drop all Linux capabilities and add back only what is needed: `--cap-drop=ALL --cap-add=NET_BIND_SERVICE`
- Use read-only root filesystems: `--read-only`
- Limit resources: `--memory=512m --cpus=1`
- Enable seccomp and AppArmor profiles to restrict syscalls
- Never mount the Docker socket (`/var/run/docker.sock`) into a container unless absolutely necessary — it grants full host control

## Kubernetes Security

**Authentication and RBAC:**
- Disable anonymous authentication on the API server
- Use RBAC with least-privilege ClusterRoles and Roles
- Bind service accounts to specific namespaces with minimal permissions
- Avoid using the `default` service account — create dedicated accounts per workload

**Pod Security:**
- Enforce Pod Security Standards (Restricted level) via admission controllers
- Set `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`
- Define resource requests and limits for CPU and memory
- Use `NetworkPolicies` to restrict pod-to-pod traffic (default is allow-all)

**Secrets management:**
- Kubernetes Secrets are base64-encoded, not encrypted at rest by default
- Enable etcd encryption at rest or use external secret stores (Vault, AWS Secrets Manager)
- Use the CSI Secrets Store Driver to mount secrets from external providers

## Supply Chain and Admission Control

- Use admission controllers (OPA/Gatekeeper, Kyverno) to enforce policies: no privileged containers, required labels, approved registries only
- Enable audit logging on the Kubernetes API server
- Implement SBOM (Software Bill of Materials) generation for all images

## Network Security in Kubernetes

- Deploy a CNI plugin that supports NetworkPolicies (Calico, Cilium)
- Default-deny all ingress and egress, then allow specific traffic per namespace and workload
- Use service mesh (Istio, Linkerd) for mTLS between services if zero-trust is required

## SOC Relevance

Container-specific alerts include: privileged container launched, container escape attempts (unexpected mount points, host PID namespace), image pulled from unapproved registry, exec into running container, and anomalous network connections from pods. Ephemeral containers complicate forensics — ensure logging is shipped externally before the container terminates.
""",
    },
    {
        "title": "Serverless Security Considerations",
        "tags": ["cloud", "serverless", "lambda", "azure-functions", "security"],
        "content": r"""# Serverless Security Considerations

Serverless computing (AWS Lambda, Azure Functions, GCP Cloud Functions) eliminates infrastructure management but introduces unique security challenges around code injection, excessive permissions, and event-driven attack surfaces.

## What Changes with Serverless

**Provider responsibilities (expanded):** The provider manages the OS, runtime patching, scaling, and resource allocation. There is no SSH access and no OS-level hardening for the customer to perform.

**Customer responsibilities (shifted):** Code security, function configuration, IAM permissions, event source validation, and secrets management remain entirely the customer's domain.

## Key Attack Vectors

**1. Event injection:**
Serverless functions are triggered by events — HTTP requests, queue messages, S3 uploads, database changes. If the event data is not validated and sanitized, injection attacks are possible.

- An S3 PUT event triggers a Lambda that processes the filename — a crafted filename with shell metacharacters could cause command injection
- An API Gateway event with unsanitized query parameters could lead to SQL injection or NoSQL injection in the function code
- A message queue event with malicious JSON payloads could exploit deserialization flaws

**2. Overprivileged execution roles:**
Developers frequently attach broad IAM policies (`AdministratorAccess`, `AmazonS3FullAccess`) to function roles for convenience. A single vulnerable function then becomes an entry point to the entire cloud account.

**3. Dependency vulnerabilities:**
Functions include third-party libraries that may contain known vulnerabilities. The small deployment packages make it easy to overlook dependency security.

**4. Secrets in environment variables:**
Serverless platforms use environment variables for configuration. Storing secrets directly in environment variables exposes them in the console UI, deployment templates, and function metadata API responses.

## Security Best Practices

**Permissions:**
- Create a dedicated IAM role per function with only the specific actions and resources it needs
- Use resource-based policies to restrict which services can invoke the function
- Set concurrency limits to prevent abuse or runaway costs

**Code security:**
- Validate and sanitize all input from event sources
- Use parameterized queries for database access
- Pin dependency versions and scan with `npm audit`, `pip-audit`, or `snyk`
- Keep function packages small — remove unused dependencies

**Secrets:**
- Store secrets in a secrets manager, not in environment variables
- Use IAM-based authentication (instance roles, workload identity) when calling other cloud services
- Encrypt sensitive environment variables with KMS

**Monitoring:**
- Enable function-level logging (CloudWatch Logs, Azure Monitor, Cloud Logging)
- Set up alarms for unusual invocation counts, error rates, and duration spikes
- Use distributed tracing (X-Ray, Application Insights) to follow requests across functions

## Cold Starts and Security Implications

Cold starts create a window where initialization code runs, potentially making network calls to fetch secrets or establish connections. If this initialization is not handled securely, it could expose timing side-channels or leak information in error messages.

## SOC Relevance

Serverless events are harder to correlate because each invocation is isolated and ephemeral. There is no persistent host to investigate. Analysts must rely on CloudWatch/Azure Monitor logs, X-Ray traces, and CloudTrail API call records. Key indicators: unexpected function invocations, calls to unusual AWS services from a function role, or data exfiltration patterns in egress traffic.
""",
    },
    {
        "title": "Infrastructure as Code Security — Terraform and Beyond",
        "tags": ["cloud", "iac", "terraform", "security", "devsecops", "misconfiguration"],
        "content": r"""# Infrastructure as Code Security — Terraform and Beyond

Infrastructure as Code (IaC) defines cloud resources in version-controlled configuration files. This is both a security advantage (repeatable, reviewable, auditable) and a risk (misconfigurations in code become misconfigurations in production at scale).

## Why IaC Security Matters

- A single misconfigured Terraform module can deploy hundreds of insecure resources across multiple accounts
- IaC templates are often the earliest point where a security issue can be caught — before any infrastructure exists
- Drift detection (where deployed resources differ from code) reveals unauthorized manual changes

## Common IaC Misconfigurations

**Network exposure:**
```hcl
# DANGEROUS — allows all inbound traffic
resource "aws_security_group_rule" "bad" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}
```

**Unencrypted storage:**
- S3 buckets without `server_side_encryption_configuration`
- RDS instances with `storage_encrypted = false`
- EBS volumes without encryption

**Overprivileged IAM:**
- IAM policies with `"Action": "*"` or `"Resource": "*"`
- Service roles with `AdministratorAccess`

**Missing logging:**
- CloudTrail not enabled
- VPC flow logs not configured
- S3 access logging disabled

## Scanning Tools

| Tool | Type | Strengths |
|---|---|---|
| **Checkov** | Static analysis | 1000+ built-in policies, Terraform/CloudFormation/K8s |
| **tfsec** (now Trivy) | Static analysis | Terraform-focused, fast, good defaults |
| **Terrascan** | Static analysis | OPA-based policies, multi-IaC |
| **KICS** | Static analysis | Broad IaC support including Ansible, Docker |
| **Sentinel** | Policy as code | HashiCorp native, integrates with Terraform Cloud |
| **OPA/Conftest** | Policy as code | Flexible Rego policies for any structured data |

## Integrating Security into the IaC Pipeline

**Pre-commit:** Run `checkov` or `tfsec` locally before pushing code. Catches obvious issues early.

**CI/CD pipeline:** Run scanning as a required check in pull requests. Block merges on high/critical findings.

**Terraform plan analysis:** Scan the plan output (not just the HCL files) to catch issues that only appear when variables are resolved.

**Post-deployment:** Use cloud-native tools (AWS Config, Azure Policy, GCP Security Health Analytics) to detect drift and runtime misconfigurations.

## Secrets in IaC

- Never hardcode secrets in `.tf` files, variable defaults, or `terraform.tfvars`
- Use `sensitive = true` on Terraform variables containing secrets
- Pull secrets from Vault, AWS Secrets Manager, or Azure Key Vault using data sources
- Add `*.tfvars`, `.terraform/`, and state files to `.gitignore`
- Terraform state files contain plaintext secrets — encrypt them (S3 backend with KMS, Terraform Cloud)

## State File Security

The Terraform state file (`terraform.tfstate`) contains the full configuration of every managed resource, including sensitive outputs and data source results.

- Store state remotely with encryption (S3 + KMS, Azure Blob + encryption, GCS + CMEK)
- Enable state locking (DynamoDB for S3 backend) to prevent concurrent modifications
- Restrict state access to the CI/CD pipeline service account
- Never commit state files to version control

## SOC Relevance

IaC pipelines are a high-value target. An attacker who compromises the CI/CD system or gains write access to the IaC repository can deploy backdoors, weaken security groups, or create new IAM users — all through legitimate-looking infrastructure changes. Monitor for unexpected plan/apply runs, changes to security-sensitive resources, and modifications to the pipeline itself.
""",
    },
]

SIEM_ANALYTICS = [
    {
        "title": "SIEM Architecture and Data Pipeline",
        "tags": ["siem", "architecture", "data-pipeline", "log-management", "elasticsearch"],
        "content": r"""# SIEM Architecture and Data Pipeline

A Security Information and Event Management (SIEM) system collects, normalizes, stores, and analyzes security-relevant data from across the enterprise. Understanding the data pipeline is essential for effective detection engineering and incident response.

## Core Components

**1. Data Collection Layer**
- **Agents:** Lightweight forwarders installed on endpoints (Elastic Agent, Splunk Universal Forwarder, Wazuh agent)
- **Syslog receivers:** Collect logs from network devices, firewalls, and legacy systems via UDP/TCP/TLS syslog
- **API integrations:** Pull logs from cloud services (CloudTrail, Azure AD, GCP), SaaS applications (O365, Okta), and threat intelligence feeds
- **Network taps / packet brokers:** Capture raw network traffic for full packet analysis or metadata extraction

**2. Ingestion and Parsing Layer**
- **Log shipper:** Filebeat, Fluentd, Logstash, or Cribl Stream
- **Parsing:** Extract structured fields from raw log messages using Grok patterns, regular expressions, or JSON parsing
- **Normalization:** Map vendor-specific field names to a common schema (ECS, OCSF, CIM) so that detection rules work across data sources
- **Enrichment:** Add context at ingest time — GeoIP, threat intelligence lookups, asset inventory tags, user identity resolution

**3. Storage Layer**
- **Hot tier:** Fast storage (SSD) for recent data (7-30 days), supports real-time search and alerting
- **Warm tier:** Standard storage for medium-term retention (30-90 days)
- **Cold / Frozen tier:** Cheap storage (object storage, HDDs) for long-term retention (1-7 years for compliance)
- **Index lifecycle management:** Automatically roll, shrink, and delete indices based on age and size

**4. Detection and Analytics Layer**
- **Correlation engine:** Matches events against detection rules in near-real-time
- **Scheduled queries:** Run at intervals to catch patterns that span time windows
- **Machine learning:** Anomaly detection for user behavior (UEBA), network traffic, and process execution
- **Threat intelligence matching:** Compare IOCs (IPs, domains, hashes) against incoming logs

**5. Response and Case Management Layer**
- **Alert queue:** Prioritized list of triggered detections for analyst review
- **Case management:** Group related alerts into incidents for investigation
- **SOAR integration:** Automate enrichment, containment, and notification workflows

## Data Volume Considerations

| Source | Typical Volume | Retention Priority |
|---|---|---|
| Endpoint (EDR) | 5-50 GB/day per 1000 hosts | High |
| Network (firewall, proxy) | 10-100 GB/day | Medium |
| Cloud audit logs | 1-10 GB/day | High |
| Authentication (AD, Okta) | 1-5 GB/day | High |
| DNS logs | 5-20 GB/day | Medium |
| Application logs | Variable | Depends on criticality |

## Common Schema: Elastic Common Schema (ECS)

ECS provides a standard field naming convention. For example:
- `source.ip`, `destination.ip`, `source.port`, `destination.port` for network events
- `user.name`, `user.domain` for identity events
- `process.name`, `process.pid`, `process.command_line` for endpoint events
- `event.category`, `event.type`, `event.outcome` for classification

## SOC Relevance

Analysts who understand the data pipeline can troubleshoot missing logs, identify parsing errors, and optimize queries. When an expected alert does not fire, the issue is often in the pipeline — a parsing failure, a dropped field, or a missing log source — not in the detection rule itself.
""",
    },
    {
        "title": "Log Source Onboarding",
        "tags": ["siem", "log-sources", "onboarding", "data-quality", "parsing"],
        "content": r"""# Log Source Onboarding

Onboarding a new log source into a SIEM is a structured process that directly impacts detection coverage, alert fidelity, and investigation capability. Rushing this process creates blind spots and generates noise.

## The Onboarding Process

**Step 1 — Identify the source and its value**
- What security-relevant events does this source produce?
- What detection use cases does it enable?
- What compliance requirements does it satisfy?
- What is the expected volume (events per second, GB per day)?

**Step 2 — Determine the collection method**
- Agent-based (Elastic Agent, Splunk UF) for endpoints and servers
- Syslog (TCP/TLS preferred over UDP) for network devices
- API polling for cloud services and SaaS platforms
- File-based collection for applications writing to local logs
- Streaming (Kafka, Event Hub, Pub/Sub) for high-volume sources

**Step 3 — Parse and normalize**
- Identify the log format (JSON, CSV, key-value, syslog, CEF, LEEF, Windows Event XML)
- Build or configure parsers to extract fields (Logstash Grok, Filebeat processors, Cribl pipelines)
- Map extracted fields to the common schema (ECS, CIM, OCSF)
- Handle multi-line events, encoding issues, and timestamp parsing
- Test parsers against sample logs — at least 100 representative events covering all event types

**Step 4 — Validate data quality**
- Confirm all expected event types are arriving
- Verify timestamps are correct and in UTC
- Check that critical fields are populated (source IP, user, action, outcome)
- Compare ingested event counts against the source's own metrics
- Look for parsing failures (events landing in a catch-all or error index)

**Step 5 — Enable detections**
- Activate relevant detection rules for the new source
- Tune thresholds based on observed baseline volumes
- Create dashboards for visibility and hunting

**Step 6 — Document and maintain**
- Record the source, collection method, parser version, retention policy, and responsible team
- Set up monitoring for ingestion health (volume drops, parsing errors, agent heartbeats)
- Schedule periodic reviews to catch schema changes from vendor updates

## Common Pitfalls

**Timestamp issues:** Many sources use local time without timezone indicators. Always parse to UTC and verify with known events. A 5-hour offset makes correlation impossible.

**Field mapping gaps:** Not every vendor includes the same fields. A firewall may log source IP but not username. Document what each source does and does not provide.

**Volume surprises:** DNS debug logging or verbose firewall rules can generate 10x more data than expected. Start with a low-volume test before enabling full collection.

**Schema drift:** Vendor software updates may change log formats. A parser that worked for v10 may break on v11. Monitor parsing success rates.

## Prioritizing Log Sources

Not all log sources are equal. Prioritize based on detection coverage:

1. **Identity providers** (AD, Okta, Azure AD) — authentication and authorization events
2. **Endpoint detection** (EDR, Sysmon) — process execution, file changes, network connections
3. **Cloud audit logs** (CloudTrail, Activity Log) — control plane operations
4. **Network perimeter** (firewall, proxy, DNS) — north-south traffic
5. **Email gateway** — phishing detection
6. **Application logs** — business-critical systems
7. **East-west network** (VPC flow logs, internal IDS) — lateral movement

## SOC Relevance

When analysts encounter a gap in visibility during an investigation, the answer is often that a critical log source was never onboarded. Maintaining a log source inventory with coverage mapping ensures the team knows what they can and cannot see.
""",
    },
    {
        "title": "Correlation Rule Design",
        "tags": ["siem", "correlation", "detection-engineering", "rules", "alerts"],
        "content": r"""# Correlation Rule Design

Correlation rules are the core detection mechanism in a SIEM. They transform raw log events into actionable security alerts. Well-designed rules catch real threats with minimal false positives; poorly designed rules bury the SOC in noise.

## Rule Types

**1. Single-event rules:**
Match individual events against specific criteria.
- Example: "Alert when a user account is created outside of business hours"
- Implementation: Simple query filter on event type + timestamp condition
- Use case: High-confidence indicators, known-bad patterns

**2. Threshold rules:**
Fire when an event count exceeds a limit within a time window.
- Example: "Alert when more than 5 failed logins occur for a single user within 10 minutes"
- Implementation: Aggregation query grouped by user, count > 5, window = 10m
- Use case: Brute force detection, scanning activity

**3. Sequence / chain rules:**
Detect an ordered sequence of events that individually are benign but together indicate malicious activity.
- Example: "Alert when a user fails login 3+ times, then successfully logs in, then accesses a sensitive file share — all within 30 minutes"
- Implementation: Event sequence with shared field (username), ordered by timestamp, time constraint
- Use case: Post-compromise activity, insider threats

**4. Anomaly rules:**
Identify deviations from baseline behavior using statistical or ML methods.
- Example: "Alert when a user accesses 10x more files than their 30-day average"
- Implementation: ML model or statistical baseline with dynamic threshold
- Use case: Data exfiltration, compromised accounts

## Design Principles

**Start with the threat:**
- What ATT&CK technique are you detecting?
- What does the attacker's action look like in log data?
- What data sources are required?

**Define true positive criteria:**
- What specifically makes this alert worth investigating?
- Write a clear description that tells the analyst what happened and why it matters

**Minimize false positives from the start:**
- Exclude known-good patterns (service accounts, scheduled tasks, known admin activity)
- Use allowlists for expected behavior rather than trying to enumerate all bad behavior
- Scope rules to relevant assets or user populations

**Set appropriate severity:**
- Critical: High-confidence indicator of active compromise
- High: Strong signal requiring prompt investigation
- Medium: Suspicious activity needing context
- Low: Informational, useful for hunting and correlation

## Rule Documentation Template

```
Name: Brute Force — Multiple Failed Logins Followed by Success
MITRE ATT&CK: T1110.001 (Brute Force: Password Guessing)
Data sources: Windows Security (4625, 4624), Azure AD Sign-in Logs
Logic: 5+ failed logins for user X in 10 min, followed by success within 5 min
Exclusions: Service accounts in allowlist, VPN gateway IPs
Severity: High
Response: Verify if source IP is expected, check for lateral movement post-login
Known FP: Password reset workflows, users with expired passwords
```

## Testing and Validation

- **Unit test:** Replay known-malicious log samples and confirm the rule fires
- **Negative test:** Replay benign activity and confirm the rule does NOT fire
- **Volume test:** Run against production data in detection-only mode for 1-2 weeks before enabling alerts
- **Red team validation:** Have the offensive team execute the technique and verify detection

## SOC Relevance

Detection engineering is an iterative process. Rules should be reviewed quarterly, tuned based on analyst feedback, and retired when no longer relevant. Every false positive wastes analyst time; every false negative is a missed threat. Track the true positive rate per rule and invest effort in the rules that matter most.
""",
    },
    {
        "title": "Alert Tuning and False Positive Reduction",
        "tags": ["siem", "alert-tuning", "false-positives", "detection", "soc-operations"],
        "content": r"""# Alert Tuning and False Positive Reduction

Alert fatigue is the most common operational failure in SOC environments. When analysts are overwhelmed with false positives, they begin ignoring or auto-closing alerts — and real threats slip through. Systematic alert tuning is not optional; it is a security control.

## Measuring the Problem

**Key metrics:**
- **True positive rate:** Percentage of alerts that represent genuine security events
- **False positive rate:** Percentage of alerts that are benign upon investigation
- **Alert volume per analyst:** Total alerts divided by analyst count per shift
- **Mean time to triage:** Average time from alert creation to first analyst action
- **Closure reason distribution:** Why alerts are being closed (true positive, false positive, duplicate, informational)

**Healthy targets:**
- True positive rate: > 50% (industry average is often 20-30%)
- Alerts per analyst per shift: < 50 (above this, quality degrades)
- Mean time to triage: < 15 minutes for high severity

## Tuning Strategies

**1. Allowlisting known-good behavior:**
- Identify service accounts, scheduled tasks, and automated processes that trigger alerts
- Add them as exclusions to the detection rule (not to a global suppression list)
- Document why each exclusion exists and review quarterly

**2. Raising thresholds:**
- If a brute force rule fires on 3 failed logins, but your environment averages 2 per user per day, raise the threshold to 10
- Base thresholds on data, not intuition — query historical data to find the right number

**3. Narrowing scope:**
- A generic "suspicious PowerShell" rule that fires on every IT admin machine is too broad
- Scope to non-admin workstations, or exclude known admin scripts by hash
- Target rules at the asset population where the threat is realistic

**4. Adding context requirements:**
- Instead of alerting on any failed login, require failed login + subsequent success + access to sensitive resource
- Correlated rules have higher fidelity because attackers must exhibit the full behavior chain

**5. Risk-based scoring:**
- Assign risk scores to individual events based on user role, asset criticality, and threat intelligence
- Only alert when the cumulative risk score for an entity exceeds a threshold
- This suppresses isolated low-risk events while catching converging indicators

## The Tuning Workflow

1. **Identify high-volume, low-value rules:** Sort rules by alert count and false positive rate
2. **Analyze false positives:** For the top offenders, examine 20-50 recent false positives to find patterns
3. **Implement tuning:** Add exclusions, adjust thresholds, or refine rule logic
4. **Test in detection-only mode:** Run the tuned rule for 1-2 weeks without alerting
5. **Measure impact:** Compare alert volume, TP rate, and MTTT before and after
6. **Document changes:** Record what was changed, why, and the expected effect
7. **Schedule review:** Revisit tuned rules quarterly to ensure exclusions are still valid

## Common Mistakes

- **Over-tuning:** Excluding too aggressively and creating blind spots. Every exclusion should be justified and documented.
- **Global suppression:** Suppressing an alert source-wide instead of refining the rule. This hides both false and true positives.
- **Ignoring instead of tuning:** Analysts marking alerts as "not interesting" without feeding back to detection engineering. This is a process failure.
- **Not tracking tuning debt:** Unmaintained rules with years-old exclusions referencing decommissioned systems.

## SOC Relevance

Alert tuning is a shared responsibility between SOC analysts and detection engineers. Analysts provide ground truth (this alert is a false positive because of X). Engineers translate that feedback into rule improvements. Without this feedback loop, detection quality degrades over time.
""",
    },
    {
        "title": "Writing Sigma Rules for Portable Detection",
        "tags": ["siem", "sigma", "detection-engineering", "rules", "portable"],
        "content": r"""# Writing Sigma Rules for Portable Detection

Sigma is an open standard for writing detection rules in a SIEM-agnostic YAML format. A single Sigma rule can be converted to queries for Elasticsearch, Splunk, Microsoft Sentinel, QRadar, and dozens of other platforms.

## Sigma Rule Structure

```yaml
title: Suspicious PowerShell Download Cradle
id: 3b6ab547-0998-4f9a-8108-3e0a7b5a13c5
status: test
description: Detects PowerShell commands commonly used to download and execute payloads
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: SOC Team
date: 2025/06/15
modified: 2025/09/20
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith: '\powershell.exe'
    selection_cmdline:
        CommandLine|contains|all:
            - 'Net.WebClient'
            - 'DownloadString'
    condition: selection_process and selection_cmdline
falsepositives:
    - Legitimate administrative scripts
    - Software deployment tools
level: high
```

## Key Fields Explained

**logsource:** Defines what kind of log data the rule targets. The `category` and `product` fields determine which backend mapping is used during conversion.

Common logsources:
- `category: process_creation, product: windows` — Sysmon EventID 1, Windows 4688
- `category: network_connection, product: windows` — Sysmon EventID 3
- `category: file_event, product: windows` — Sysmon EventID 11
- `category: proxy` — Web proxy logs
- `category: firewall` — Network firewall logs

**detection:** The core logic. Uses selections (conditions that must match) combined with a boolean condition.

**Modifiers:**
- `|contains` — Substring match
- `|endswith`, `|startswith` — Anchored substring
- `|all` — All values in a list must match (AND logic; without this, lists use OR)
- `|re` — Regular expression
- `|base64` — Decode base64 before matching
- `|cidr` — CIDR network matching

## Writing Effective Sigma Rules

**1. Target specific techniques:**
Each rule should map to one or two ATT&CK techniques. Rules that try to detect too many things become impossible to tune.

**2. Use robust field matching:**
Prefer `|contains` over exact matches for command lines, as attackers add spaces, use alternate casing, and obfuscate. But be specific enough to avoid excessive false positives.

**3. Layer selections for precision:**
```yaml
detection:
    selection_parent:
        ParentImage|endswith: '\outlook.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
    condition: selection_parent and selection_child
```
This detects suspicious child processes spawned from Outlook — a classic phishing indicator.

**4. Document false positives:**
Every Sigma rule should list known false positive scenarios. This helps analysts and future rule maintainers.

## Converting Sigma Rules

Use `sigma-cli` to convert rules to your SIEM's query language:

```bash
# Convert to Elasticsearch Lucene query
sigma convert -t lucene rule.yml

# Convert to Splunk SPL
sigma convert -t splunk rule.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t microsoft365defender rule.yml
```

## SigmaHQ Repository

The SigmaHQ GitHub repository contains 3000+ community-maintained rules covering common attack techniques. Use these as a starting point, then customize for your environment.

**Integration workflow:**
1. Clone or subscribe to SigmaHQ releases
2. Convert rules to your SIEM format
3. Test against your environment data
4. Tune false positives for your specific baseline
5. Deploy to production detection pipeline

## SOC Relevance

Sigma rules are the detection-as-code equivalent of infrastructure-as-code. They can be version-controlled, peer-reviewed in pull requests, tested in CI/CD, and shared across organizations. Analysts who can write and modify Sigma rules directly contribute to the team's detection coverage without being locked into a specific SIEM vendor.
""",
    },
    {
        "title": "SIEM Query Syntax — KQL and Lucene",
        "tags": ["siem", "kql", "lucene", "elasticsearch", "query", "search"],
        "content": r"""# SIEM Query Syntax — KQL and Lucene

Query languages are the analyst's primary interface with SIEM data. Proficiency in KQL (Kibana Query Language) and Lucene enables faster triage, more effective hunting, and better detection rule development.

## Lucene Query Syntax (Elasticsearch)

Lucene is the underlying query language for Elasticsearch. It supports field-level searches, wildcards, ranges, and boolean operators.

**Basic field search:**
```
event.action: "user-login-failed"
source.ip: 10.0.0.0/8
destination.port: 443
```

**Boolean operators:**
```
event.action: "login" AND event.outcome: "failure"
source.ip: 192.168.1.100 OR source.ip: 192.168.1.101
NOT user.name: "svc_backup"
```

**Wildcards:**
```
process.name: powershell*
user.name: admin?
url.path: */wp-admin/*
```

**Ranges:**
```
destination.port: [1024 TO 65535]
event.risk_score: [75 TO *]
@timestamp: [2025-01-01 TO 2025-01-31]
```

**Phrase search (exact order):**
```
process.command_line: "Invoke-Expression (New-Object Net.WebClient)"
```

**Escaping special characters:**
Lucene reserves `+ - = && || > < ! ( ) { } [ ] ^ " ~ * ? : \ /`. Escape with backslash.

## KQL (Kibana Query Language)

KQL is a simplified query language available in Kibana's search bar. It is more intuitive than Lucene but less powerful for complex queries.

**Basic search:**
```
event.action: "user-login-failed"
source.ip: 10.0.0.0/8
```

**Boolean operators:**
```
event.action: "login" and event.outcome: "failure"
source.ip: 192.168.1.100 or source.ip: 192.168.1.101
not user.name: "svc_backup"
```

**Wildcards:**
```
process.name: powershell*
host.name: web-server-*
```

**Nested field queries:**
```
observer.geo.country_name: "Russia" or observer.geo.country_name: "China"
```

**Key difference from Lucene:** KQL does not support regular expressions, ranges with bracket syntax, or proximity searches. For these, switch to Lucene mode in Kibana.

## Microsoft Sentinel KQL (Kusto)

Azure Sentinel uses Kusto Query Language, which is a pipe-based language quite different from Lucene/KQL.

```kusto
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedAttempts = count() by TargetAccount, IpAddress
| where FailedAttempts > 10
| sort by FailedAttempts desc
```

**Key operators:**
- `where` — Filter rows
- `summarize` — Aggregate (count, sum, avg, dcount)
- `extend` — Add calculated columns
- `project` — Select specific columns
- `join` — Combine tables
- `render` — Visualize results

## Practical Hunt Queries

**Failed logins followed by success (Lucene):**
```
event.category: "authentication" AND event.outcome: "failure"
```
Then pivot to the same user:
```
user.name: "jsmith" AND event.category: "authentication" AND event.outcome: "success"
```

**Rare process execution (Kusto):**
```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| summarize ExecutionCount = count() by FileName
| where ExecutionCount < 5
| sort by ExecutionCount asc
```

**DNS queries to unusual TLDs (Lucene):**
```
dns.question.name: (*.tk OR *.ml OR *.ga OR *.cf OR *.top OR *.xyz)
```

## SOC Relevance

Query proficiency directly correlates with investigation speed. An analyst who can write precise queries spends minutes on what would take an unskilled searcher hours of scrolling through raw events. Practice writing queries for common scenarios: authentication anomalies, process execution, network connections, and DNS lookups.
""",
    },
    {
        "title": "SOAR Concepts and Automation",
        "tags": ["siem", "soar", "automation", "orchestration", "playbooks"],
        "content": r"""# SOAR Concepts and Automation

Security Orchestration, Automation, and Response (SOAR) platforms connect security tools, automate repetitive tasks, and orchestrate incident response workflows. When implemented well, SOAR multiplies analyst capacity. When implemented poorly, it creates a fragile automation layer that obscures visibility.

## The Three Pillars

**Orchestration:** Connecting disparate security tools through APIs so they can share data and trigger actions across platforms. The SOAR platform acts as a central hub between the SIEM, EDR, firewall, ticketing system, threat intel platform, and email gateway.

**Automation:** Replacing manual, repetitive analyst tasks with programmatic workflows. Automation handles the predictable steps so analysts can focus on judgment-intensive decisions.

**Response:** Enabling faster and more consistent incident response through predefined playbooks that guide or execute response actions.

## What to Automate

**High value, low risk — automate fully:**
- Alert enrichment (GeoIP, threat intel lookups, asset/user context)
- Reputation checks (VirusTotal, AbuseIPDB, URLhaus)
- Ticket creation and assignment
- Notification distribution (Slack, email, PagerDuty)
- IOC extraction from alerts and reports

**Medium value, medium risk — automate with human approval:**
- User account disabling (require analyst confirmation)
- Firewall block rules (require analyst review of the IP/domain)
- Email quarantine (require analyst verification of phishing)
- Endpoint isolation (require analyst confirmation of compromise)

**Low value for automation — keep manual:**
- Root cause analysis
- Incident scoping and impact assessment
- Communication with affected parties
- Post-incident review and lessons learned

## Playbook Design

A SOAR playbook is a workflow that defines the automated response to a specific alert type.

**Example — Phishing Response Playbook:**
1. **Trigger:** Alert from email gateway — suspected phishing
2. **Extract IOCs:** Parse sender address, URLs, attachment hashes
3. **Enrich:** Check URLs against VirusTotal, URLhaus; check sender reputation
4. **Decide:** If any IOC is known-malicious, proceed automatically; if unknown, pause for analyst review
5. **Contain:** Quarantine the email from all recipient mailboxes
6. **Block:** Add sender domain and malicious URLs to email gateway blocklist
7. **Search:** Query SIEM for other recipients who clicked the link
8. **Notify:** Alert affected users and their managers
9. **Document:** Create incident ticket with all enrichment data and actions taken
10. **Close:** If no click-through detected, auto-close with summary

## Integration Architecture

```
SIEM Alert → SOAR Platform → Enrichment APIs (TI, Asset DB)
                            → Response APIs (EDR, Firewall, IAM)
                            → Ticketing (Jira, ServiceNow)
                            → Communication (Slack, Email)
```

## Metrics and Measurement

- **Mean time to respond (MTTR):** Measure before and after SOAR implementation
- **Analyst time saved:** Track hours recovered per week from automated tasks
- **Playbook execution count:** How often each playbook runs
- **Failure rate:** How often playbooks fail due to API errors or logic issues
- **Human intervention rate:** Percentage of playbook runs requiring analyst override

## Common Pitfalls

- **Automating before understanding:** If the manual process is not well-defined and documented, automating it will produce unreliable results
- **Over-automation:** Taking containment actions without sufficient confidence leads to business disruption (blocking a legitimate partner's domain, disabling a VIP's account)
- **Ignoring failures:** SOAR playbooks fail silently when APIs change, credentials expire, or rate limits are hit. Monitor playbook health.
- **Tool sprawl:** SOAR platforms can become a maintenance burden if every integration is custom-built. Prefer native integrations and standard APIs.

## SOC Relevance

SOAR does not replace analysts — it amplifies them. The goal is to automate the first 5-10 minutes of investigation (enrichment, context gathering, deduplication) so the analyst starts with a complete picture instead of a raw alert. Analysts should participate in playbook design to ensure the automation reflects actual investigation workflows.
""",
    },
    {
        "title": "SOC Metrics and KPIs",
        "tags": ["siem", "soc", "metrics", "kpis", "performance", "operations"],
        "content": r"""# SOC Metrics and KPIs

What gets measured gets managed. SOC metrics provide visibility into operational effectiveness, detection coverage, and team performance. Without metrics, security leadership cannot make informed decisions about staffing, tooling, or process improvements.

## Operational Metrics

**Mean Time to Detect (MTTD):**
The average time between an event occurring and the SOC detecting it. This measures detection capability and log ingestion latency.
- Target: < 1 hour for critical assets
- Influenced by: Detection rule coverage, log ingestion delay, analyst staffing

**Mean Time to Acknowledge (MTTA):**
Time from alert creation to first analyst action (opening, reading, beginning triage).
- Target: < 15 minutes for critical severity
- Influenced by: Alert queue volume, shift staffing, notification mechanisms

**Mean Time to Respond (MTTR):**
Time from detection to containment or remediation. This measures the full response chain.
- Target: < 4 hours for critical incidents
- Influenced by: Playbook maturity, SOAR automation, escalation efficiency

**Mean Time to Resolve (MTTR-resolve):**
Time from detection to full resolution (root cause identified, remediation complete, monitoring confirmed).
- Target: Varies by incident type (hours for malware, weeks for APT)

## Detection Quality Metrics

**True Positive Rate:**
Percentage of alerts that represent actual security events requiring action.
- Target: > 50%
- Calculation: True positives / (True positives + False positives)

**False Positive Rate:**
Percentage of alerts that are benign upon investigation.
- Action: Rules with > 80% FP rate should be tuned or disabled

**Detection Coverage:**
Percentage of ATT&CK techniques for which the SOC has at least one detection rule.
- Measure using ATT&CK Navigator heatmaps
- Focus on techniques relevant to your threat model, not blanket coverage

**Alert Volume:**
Total alerts generated per day/week/month, segmented by severity and source.
- Track trends to spot log source issues (sudden drops) or rule problems (sudden spikes)

## Analyst Performance Metrics

**Alerts handled per analyst per shift:**
Measures individual throughput. Watch for extremes — very high numbers may indicate rubber-stamping, very low may indicate investigation quality issues or tooling problems.

**Escalation rate:**
Percentage of alerts escalated to Tier 2/3 or incident response. A healthy escalation rate is 5-15%. Too high suggests Tier 1 lacks context or training; too low may indicate under-escalation.

**Feedback loop participation:**
How often analysts provide tuning feedback to detection engineering. This is a qualitative metric but critical for detection improvement.

## Reporting Cadences

| Cadence | Audience | Content |
|---|---|---|
| Daily | SOC lead / shift handoff | Alert volume, critical incidents, pending items |
| Weekly | SOC management | MTTD/MTTR trends, TP rate, tuning backlog |
| Monthly | CISO / security leadership | Coverage gaps, staffing analysis, tool effectiveness |
| Quarterly | Executive / board | Risk posture summary, incident trends, investment ROI |

## Building a Metrics Dashboard

Essential dashboard panels:
- Alert volume over time (line chart, segmented by severity)
- MTTD / MTTA / MTTR trend lines
- Top 10 noisiest detection rules (for tuning prioritization)
- Alert closure reason breakdown (pie chart)
- Detection coverage heatmap (ATT&CK matrix)
- Analyst workload distribution (bar chart)

## Anti-Patterns

- **Vanity metrics:** "We processed 10,000 alerts this month" says nothing about security outcomes
- **Punitive metrics:** Using alert-handling speed to punish analysts incentivizes skipping investigation
- **Measuring without acting:** Tracking MTTD for a year without investing in faster detection is theater
- **Ignoring context:** MTTR of 2 hours means different things for a phishing email vs. an APT intrusion

## SOC Relevance

Metrics are tools for continuous improvement, not performance reviews. The goal is to identify systemic issues — a rule generating 500 false positives per week, an understaffed night shift, a log source with 4-hour ingestion delay — and fix them. Share metrics transparently with the team so everyone understands where the bottlenecks are.
""",
    },
]

GOVERNANCE = [
    {
        "title": "ISO 27001 Overview — Information Security Management",
        "tags": ["governance", "iso-27001", "isms", "compliance", "standards"],
        "content": r"""# ISO 27001 Overview — Information Security Management

ISO/IEC 27001 is the international standard for establishing, implementing, maintaining, and continually improving an Information Security Management System (ISMS). It is the most widely recognized security certification globally and is often a prerequisite for enterprise contracts.

## What Is an ISMS?

An ISMS is a systematic approach to managing sensitive information so that it remains secure. It encompasses people, processes, and technology. ISO 27001 does not prescribe specific technologies — it defines a management framework within which an organization selects appropriate controls.

## Structure of the Standard

**Clauses 4-10 (Management System Requirements):**
- **Clause 4 — Context:** Understand internal/external issues, interested parties, and ISMS scope
- **Clause 5 — Leadership:** Top management commitment, security policy, organizational roles
- **Clause 6 — Planning:** Risk assessment methodology, risk treatment plan, security objectives
- **Clause 7 — Support:** Resources, competence, awareness, communication, documented information
- **Clause 8 — Operation:** Implement risk treatment plan, manage changes
- **Clause 9 — Performance Evaluation:** Monitoring, internal audit, management review
- **Clause 10 — Improvement:** Nonconformities, corrective actions, continual improvement

**Annex A (Control Objectives):**
ISO 27001:2022 contains 93 controls organized into four themes:
- **Organizational controls** (37): Policies, roles, asset management, supplier relationships
- **People controls** (8): Screening, awareness, responsibilities, termination
- **Physical controls** (14): Perimeters, entry, equipment, storage media
- **Technological controls** (34): Access management, cryptography, logging, network security

## The Certification Process

1. **Gap analysis:** Assess current state against ISO 27001 requirements
2. **Risk assessment:** Identify assets, threats, vulnerabilities, and calculate risk
3. **Statement of Applicability (SoA):** Document which Annex A controls are applicable and justify exclusions
4. **Implement controls:** Deploy technical, administrative, and physical controls
5. **Internal audit:** Verify compliance with your own ISMS policies
6. **Management review:** Senior leadership reviews ISMS effectiveness
7. **Stage 1 audit (documentation):** External auditor reviews ISMS documentation
8. **Stage 2 audit (implementation):** External auditor verifies controls are implemented and effective
9. **Certification:** 3-year certificate issued, with annual surveillance audits

## Risk Assessment Approach

ISO 27001 requires a risk-based approach but does not mandate a specific methodology. Common frameworks include:
- Asset-based: Identify assets → threats → vulnerabilities → calculate risk
- Scenario-based: Identify threat scenarios → assess likelihood and impact
- ISO 27005: Companion standard providing detailed risk management guidance

## Common Pitfalls

- Treating certification as a one-time project rather than an ongoing program
- Creating policies that do not reflect actual practice ("paper ISMS")
- Failing to integrate security objectives into business operations
- Underestimating the effort required for documentation and evidence collection

## SOC Relevance

ISO 27001 requires monitoring and logging (Annex A 8.15-8.16), incident management (A 5.24-5.28), and evidence collection (A 5.28). SOC operations directly support multiple ISMS controls. Analysts may be asked to provide evidence of monitoring effectiveness during audit activities.
""",
    },
    {
        "title": "NIST Cybersecurity Framework (CSF)",
        "tags": ["governance", "nist", "csf", "framework", "risk-management"],
        "content": r"""# NIST Cybersecurity Framework (CSF)

The NIST Cybersecurity Framework is a voluntary framework that provides a common language for managing cybersecurity risk. Originally developed for US critical infrastructure, it has been adopted globally across industries. CSF 2.0 (released February 2024) added a sixth function and expanded the framework's applicability.

## The Six Functions (CSF 2.0)

**GOVERN (GV) — New in 2.0:**
Establishes the organizational context, strategy, and governance for managing cybersecurity risk. This function emphasizes that cybersecurity is a leadership responsibility, not just a technical one.
- Risk management strategy and appetite
- Roles, responsibilities, and authorities
- Policy development and communication
- Supply chain risk management oversight

**IDENTIFY (ID):**
Understand the organizational context and the resources that support critical functions.
- Asset management (hardware, software, data, systems)
- Business environment and critical service dependencies
- Risk assessment and threat landscape analysis
- Improvement opportunities

**PROTECT (PR):**
Implement safeguards to ensure delivery of critical services.
- Identity management and access control
- Security awareness and training
- Data security (encryption, DLP, classification)
- Platform security (hardening, patching)
- Technology infrastructure resilience

**DETECT (DE):**
Develop and implement activities to identify cybersecurity events.
- Continuous monitoring of networks, systems, and users
- Adverse event analysis (correlation, anomaly detection)
- Event detection processes and procedures

**RESPOND (RS):**
Take action regarding detected cybersecurity incidents.
- Incident management (triage, analysis, escalation)
- Incident reporting (internal and external)
- Incident mitigation and containment

**RECOVER (RC):**
Maintain plans for resilience and restore capabilities impaired by incidents.
- Incident recovery plan execution
- Communication during recovery
- Improvements based on lessons learned

## Implementation Tiers

Tiers describe the degree of rigor in an organization's cybersecurity practices:

| Tier | Name | Description |
|---|---|---|
| 1 | Partial | Ad hoc, reactive, limited awareness |
| 2 | Risk Informed | Practices exist but not organization-wide |
| 3 | Repeatable | Formal policies, regularly updated |
| 4 | Adaptive | Continuously improving based on lessons learned and predictive indicators |

## Framework Profiles

A **Profile** is a customized alignment of the Framework's functions, categories, and subcategories to an organization's specific requirements, risk tolerance, and resources.

- **Current Profile:** Where the organization is today
- **Target Profile:** Where it needs to be
- **Gap analysis:** The difference drives a prioritized action plan

## Relationship to Other Frameworks

NIST CSF maps to:
- **ISO 27001** — CSF categories align with Annex A controls
- **CIS Controls v8** — Implementation-level guidance for CSF subcategories
- **NIST 800-53** — Detailed control catalog that provides specific control implementations
- **MITRE ATT&CK** — Maps to the DETECT and RESPOND functions

## SOC Relevance

The DETECT and RESPOND functions map directly to SOC operations. SOC teams implementing the CSF should be able to demonstrate: what data sources they monitor (DE.CM), how adverse events are analyzed (DE.AE), how incidents are managed (RS.MA), and how they report incidents (RS.CO). CSF assessments often result in actionable improvements for SOC tooling, staffing, and processes.
""",
    },
    {
        "title": "SOC 2 Essentials",
        "tags": ["governance", "soc2", "compliance", "audit", "trust-services"],
        "content": r"""# SOC 2 Essentials

SOC 2 (System and Organization Controls 2) is an audit framework developed by the AICPA that evaluates how a service organization manages data. It is the de facto compliance standard for SaaS companies and technology service providers.

## Trust Services Criteria (TSC)

SOC 2 evaluates controls against five Trust Services Criteria:

**1. Security (Common Criteria — required):**
Protection of system resources against unauthorized access. This is the only mandatory criterion and covers:
- Logical and physical access controls
- System operations and change management
- Risk mitigation
- Monitoring and incident response

**2. Availability:**
System is operational and accessible as committed. Covers:
- Performance monitoring
- Disaster recovery and business continuity
- Capacity planning
- Incident response for availability events

**3. Processing Integrity:**
System processing is complete, valid, accurate, timely, and authorized. Covers:
- Input validation and output reconciliation
- Error handling and correction
- Quality assurance processes

**4. Confidentiality:**
Information designated as confidential is protected. Covers:
- Data classification and handling
- Encryption at rest and in transit
- Access restrictions on confidential data
- Secure data disposal

**5. Privacy:**
Personal information is collected, used, retained, disclosed, and disposed of in accordance with commitments. Covers:
- Privacy notice and consent
- Data subject rights (access, correction, deletion)
- Data retention and disposal policies

## Type I vs. Type II

**Type I:** Evaluates the design of controls at a specific point in time. "Do these controls exist and are they designed appropriately?" Faster and cheaper but provides limited assurance.

**Type II:** Evaluates the operating effectiveness of controls over a period (typically 6-12 months). "Do these controls work consistently?" This is what most customers and partners require.

## The Audit Process

1. **Readiness assessment:** Identify gaps against the Trust Services Criteria
2. **Remediation:** Implement or improve controls to close gaps
3. **Evidence collection:** Gather documentation for the audit period (policies, configurations, logs, tickets)
4. **Auditor fieldwork:** CPA firm tests controls through inquiry, observation, inspection, and re-performance
5. **Report issuance:** Auditor delivers the SOC 2 report with opinion and detailed control descriptions
6. **Ongoing monitoring:** Maintain controls and prepare for the next audit period

## Common Control Examples

| Category | Control | Evidence |
|---|---|---|
| Access control | MFA required for all users | SSO configuration screenshot, exception list |
| Change management | Code reviews required before deployment | Pull request approvals in Git |
| Monitoring | Security events are logged and reviewed | SIEM dashboards, alert triage records |
| Incident response | Incidents are documented and resolved | Incident tickets with timelines |
| Encryption | Data encrypted at rest and in transit | TLS configuration, disk encryption settings |
| Background checks | Employees screened before hiring | HR process documentation |

## Key Differences from ISO 27001

- SOC 2 is an **attestation** (auditor opinion), not a certification
- SOC 2 reports are **restricted use** (shared under NDA), not public certifications
- SOC 2 is more common in North America; ISO 27001 is more common internationally
- SOC 2 Type II requires an audit **period** (usually 12 months); ISO 27001 audits are point-in-time with surveillance

## SOC Relevance

SOC operations directly support the Security criterion through continuous monitoring, incident detection and response, and access anomaly detection. During SOC 2 audits, the security operations team may need to demonstrate: alert triage procedures, incident response records, monitoring coverage evidence, and access review participation.
""",
    },
    {
        "title": "GDPR Requirements for Security Teams",
        "tags": ["governance", "gdpr", "privacy", "data-protection", "compliance"],
        "content": r"""# GDPR Requirements for Security Teams

The General Data Protection Regulation (GDPR) is the European Union's data protection law that governs how organizations collect, process, store, and share personal data of individuals in the EU/EEA. It applies to any organization worldwide that handles EU residents' data.

## Core Principles (Article 5)

1. **Lawfulness, fairness, and transparency:** Processing must have a legal basis and be clearly communicated
2. **Purpose limitation:** Data collected for a specific purpose must not be used for other purposes
3. **Data minimization:** Collect only the minimum data necessary for the stated purpose
4. **Accuracy:** Keep personal data accurate and up to date
5. **Storage limitation:** Retain data only as long as necessary
6. **Integrity and confidentiality:** Protect data against unauthorized access, loss, or destruction
7. **Accountability:** Demonstrate compliance with all principles

## Legal Bases for Processing (Article 6)

- **Consent:** Individual has given clear consent for a specific purpose
- **Contract:** Processing is necessary to fulfill a contract with the individual
- **Legal obligation:** Processing is required by law
- **Vital interests:** Processing is necessary to protect someone's life
- **Public interest:** Processing is necessary for a task in the public interest
- **Legitimate interests:** Processing is necessary for legitimate interests, balanced against individual rights

## Data Subject Rights

| Right | Description | Response Time |
|---|---|---|
| Access (Art. 15) | Obtain copy of their data and processing details | 30 days |
| Rectification (Art. 16) | Correct inaccurate personal data | 30 days |
| Erasure (Art. 17) | Request deletion of their data ("right to be forgotten") | 30 days |
| Restrict processing (Art. 18) | Limit how data is used | 30 days |
| Data portability (Art. 20) | Receive data in machine-readable format | 30 days |
| Object (Art. 21) | Object to processing based on legitimate interests | Without delay |

## Data Breach Notification (Articles 33-34)

**Notification to supervisory authority (Article 33):**
- Within **72 hours** of becoming aware of a personal data breach
- Must include: nature of breach, categories and approximate number of data subjects affected, likely consequences, measures taken or proposed
- If notification is not made within 72 hours, the reasons for delay must be explained

**Notification to data subjects (Article 34):**
- Required when the breach is likely to result in a **high risk** to individuals' rights and freedoms
- Must describe the breach in clear, plain language
- Not required if: data was encrypted, subsequent measures eliminate the risk, or individual notification would require disproportionate effort (public communication is acceptable instead)

## Security Requirements (Article 32)

GDPR requires "appropriate technical and organizational measures" including:
- Pseudonymization and encryption of personal data
- Ability to ensure ongoing confidentiality, integrity, availability, and resilience
- Ability to restore access to personal data in a timely manner after an incident
- Regular testing, assessing, and evaluating the effectiveness of security measures

## Penalties

- **Tier 1:** Up to 10 million EUR or 2% of annual global revenue (whichever is higher) — for violations of technical measures, DPO requirements, records of processing
- **Tier 2:** Up to 20 million EUR or 4% of annual global revenue — for violations of data processing principles, lawful basis, data subject rights, international transfers

## SOC Relevance

SOC teams play a critical role in GDPR compliance:
- **Breach detection:** GDPR's 72-hour notification window starts when the organization "becomes aware." SOC detection speed directly impacts compliance ability.
- **Incident classification:** Analysts must determine if an incident involves personal data and assess risk to data subjects
- **Evidence preservation:** Maintain forensic evidence while respecting data minimization principles
- **Log management:** Security logs containing personal data (usernames, IP addresses, email addresses) are themselves subject to GDPR. Ensure retention policies are justified and documented.
""",
    },
    {
        "title": "PCI DSS Key Requirements",
        "tags": ["governance", "pci-dss", "compliance", "payment-security", "cardholder-data"],
        "content": r"""# PCI DSS Key Requirements

The Payment Card Industry Data Security Standard (PCI DSS) is a set of security requirements for any organization that stores, processes, or transmits cardholder data. PCI DSS v4.0 (effective March 2024, mandatory March 2025) introduced significant updates including customized approaches and enhanced authentication requirements.

## The 12 Requirements (PCI DSS v4.0)

**Build and Maintain a Secure Network:**
1. Install and maintain network security controls (firewalls, WAF, microsegmentation)
2. Apply secure configurations to all system components (remove defaults, harden)

**Protect Account Data:**
3. Protect stored account data (encryption, masking, tokenization, truncation)
4. Protect cardholder data with strong cryptography during transmission over open networks

**Maintain a Vulnerability Management Program:**
5. Protect all systems and networks from malicious software (antivirus, EDR)
6. Develop and maintain secure systems and software (patching, secure SDLC)

**Implement Strong Access Control Measures:**
7. Restrict access to system components and cardholder data by business need to know
8. Identify users and authenticate access to system components (MFA, strong passwords)
9. Restrict physical access to cardholder data

**Regularly Monitor and Test Networks:**
10. Log and monitor all access to system components and cardholder data
11. Test security of systems and networks regularly (vulnerability scans, penetration tests)

**Maintain an Information Security Policy:**
12. Support information security with organizational policies and programs

## Cardholder Data Environment (CDE)

The CDE includes all systems, people, and processes that store, process, or transmit cardholder data, plus any systems connected to them. Minimizing the CDE through segmentation, tokenization, and outsourcing to PCI-compliant providers reduces scope and audit burden.

**Cardholder data elements:**
- Primary Account Number (PAN) — always protected
- Cardholder name, expiration date, service code — protected if stored with PAN
- Full track data, CVV/CVC, PIN — **never** stored after authorization

## Key Changes in PCI DSS v4.0

- **Customized approach:** Organizations can meet requirements using alternative controls if they demonstrate equivalent security
- **Targeted risk analysis:** Requirements now specify when a targeted risk analysis is needed to determine control frequency
- **Enhanced authentication:** MFA required for all access into the CDE (not just remote access)
- **Web application security:** WAF or equivalent required for all public-facing web applications
- **Automated log review:** Automated mechanisms required for reviewing audit logs (manual review alone is no longer sufficient)
- **Internal vulnerability scanning:** Authenticated scanning required

## Requirement 10 — Logging Deep Dive

Requirement 10 is most relevant to SOC operations:
- 10.2: Audit logs must record: user access, actions by privileged users, access to audit logs, invalid access attempts, changes to authentication mechanisms, log initialization/pausing/stopping, creation/deletion of system objects
- 10.3: Audit logs must be protected from destruction and unauthorized modification
- 10.4: Audit logs must be reviewed at least daily using automated mechanisms
- 10.5: Audit log history must be retained for at least 12 months (3 months immediately available)
- 10.7: Failures of critical security control systems must be detected, alerted, and responded to promptly

## Compliance Validation

| Merchant Level | Annual Transactions | Validation |
|---|---|---|
| Level 1 | > 6 million | On-site audit by QSA |
| Level 2 | 1-6 million | SAQ or on-site audit |
| Level 3 | 20,000-1 million (e-commerce) | SAQ |
| Level 4 | < 20,000 (e-commerce) or < 1 million | SAQ |

## SOC Relevance

SOC teams are directly responsible for PCI DSS Requirements 10 (logging and monitoring) and 11 (security testing). Daily log review must be documented and demonstrable. Intrusion detection systems must be monitored. Security incidents in the CDE require specific response procedures including preservation of evidence for forensic investigation by a PCI Forensic Investigator (PFI) if a breach is confirmed.
""",
    },
    {
        "title": "Vulnerability Management Lifecycle",
        "tags": ["governance", "vulnerability-management", "patching", "risk", "cve"],
        "content": r"""# Vulnerability Management Lifecycle

Vulnerability management is the continuous process of identifying, classifying, prioritizing, remediating, and verifying security weaknesses across an organization's technology stack. It is not just scanning and patching — it is a risk management discipline.

## The Lifecycle Phases

### 1. Discovery and Inventory

You cannot protect what you do not know exists. Maintain a current inventory of:
- **Hardware assets:** Servers, workstations, network devices, IoT/OT devices, cloud instances
- **Software assets:** Operating systems, applications, libraries, firmware versions
- **Cloud resources:** VMs, containers, serverless functions, managed services, storage buckets
- **Shadow IT:** Unauthorized applications, personal devices, rogue cloud accounts

**Tools:** Asset discovery scanners, CMDB, cloud asset inventory APIs, network scanning (Nmap), passive network monitoring.

### 2. Vulnerability Assessment

Identify known vulnerabilities in discovered assets:
- **Authenticated scanning:** Agent-based or credentialed scans that see installed packages and configurations (Nessus, Qualys, Rapid7 InsightVM)
- **Unauthenticated scanning:** Network-based scans that identify externally visible vulnerabilities
- **Container scanning:** Scan images in registries and running containers (Trivy, Grype)
- **Code scanning:** Static analysis (SAST) and software composition analysis (SCA) in CI/CD pipelines
- **Cloud configuration scanning:** CSPM tools that check for misconfigurations (Prowler, ScoutSuite)

### 3. Prioritization

Not all vulnerabilities are equal. Prioritize based on:

**CVSS score (base):** Industry-standard severity rating (0-10). Useful but insufficient alone — a CVSS 9.8 in an isolated lab system is lower priority than a CVSS 7.0 on an internet-facing payment server.

**Exploit availability:** Is there a public exploit? Is it being used in the wild? Track via CISA KEV (Known Exploited Vulnerabilities catalog), ExploitDB, and threat intelligence feeds.

**Asset criticality:** Business impact if the asset is compromised. Crown jewel systems (payment processing, domain controllers, customer databases) get highest priority.

**Exposure:** Is the asset internet-facing, internal-only, or isolated? External exposure dramatically increases risk.

**Compensating controls:** Are there mitigations in place (WAF, network segmentation, EDR) that reduce exploitability?

### 4. Remediation

**Patching:** The preferred remediation. Apply vendor patches within defined SLAs:
- Critical/actively exploited: 24-72 hours
- High severity: 7-14 days
- Medium severity: 30 days
- Low severity: 90 days or next maintenance window

**Workarounds:** When patching is not immediately possible — disable vulnerable features, restrict network access, add WAF rules, increase monitoring.

**Risk acceptance:** For vulnerabilities that cannot be remediated and have low risk, document the decision with business owner approval and set a review date.

### 5. Verification

After remediation, verify the fix was effective:
- Re-scan the affected assets to confirm the vulnerability is resolved
- Check that the patch did not introduce regressions or break functionality
- Update the vulnerability tracking system with resolution status

### 6. Reporting and Metrics

**Key metrics:**
- **Mean time to remediate (MTTR):** Average time from discovery to fix, segmented by severity
- **Scan coverage:** Percentage of assets included in regular scanning
- **Vulnerability density:** Open vulnerabilities per asset or per business unit
- **SLA compliance:** Percentage of vulnerabilities remediated within defined timeframes
- **Aging vulnerabilities:** Count of vulnerabilities open beyond their SLA

## SOC Relevance

SOC analysts use vulnerability data to contextualize alerts. A brute force attempt against a server with a known authentication bypass vulnerability is far more critical than the same attempt against a fully patched system. Integrating vulnerability scan results into the SIEM enables risk-based alert prioritization and helps analysts make faster triage decisions.
""",
    },
    {
        "title": "Third-Party Risk Management",
        "tags": ["governance", "tprm", "vendor-risk", "supply-chain", "due-diligence"],
        "content": r"""# Third-Party Risk Management

Third-party risk management (TPRM) is the process of identifying, assessing, and mitigating risks introduced by external vendors, suppliers, and service providers. Supply chain attacks and vendor breaches have made TPRM a board-level concern.

## Why TPRM Matters

- **SolarWinds (2020):** Nation-state actors compromised a software vendor's build system, distributing malware to 18,000 customers through legitimate software updates
- **Kaseya (2021):** Ransomware deployed through a managed service provider's remote management tool, affecting over 1,500 downstream organizations
- **MOVEit (2023):** A vulnerability in a file transfer tool exposed data across hundreds of organizations that used the software

The common thread: organizations were breached not through their own systems but through trusted third parties.

## The TPRM Lifecycle

### 1. Vendor Identification and Categorization

Maintain a complete inventory of third parties and classify them by risk:

| Tier | Criteria | Assessment Depth |
|---|---|---|
| Critical | Access to sensitive data, critical system dependencies, single points of failure | Full security assessment, on-site audit |
| High | Access to internal networks, processes significant data | Detailed questionnaire, evidence review |
| Medium | Limited data access, non-critical services | Standard questionnaire |
| Low | No data access, commodity services | Self-attestation |

### 2. Due Diligence and Assessment

**Pre-contract assessment:**
- Security questionnaire (SIG, CAIQ, or custom)
- Review certifications and audit reports (SOC 2 Type II, ISO 27001, PCI DSS)
- Evaluate their security architecture and controls
- Check for past breaches, legal actions, and financial stability
- Assess their own third-party management practices (fourth-party risk)

**Key areas to evaluate:**
- Data handling: encryption, access controls, retention, disposal
- Incident response: notification timelines, breach experience
- Business continuity: disaster recovery, redundancy, geographic diversity
- Access management: how they protect credentials for your systems
- Compliance: regulatory requirements relevant to your data

### 3. Contractual Controls

Embed security requirements in contracts:
- **Data protection clauses:** Specify how your data must be protected, where it can be stored, and who can access it
- **Right to audit:** Reserve the right to assess the vendor's security posture
- **Breach notification:** Require notification within a specific timeframe (24-72 hours)
- **Subcontractor restrictions:** Require approval for subcontractors who will handle your data
- **Data return/destruction:** Define what happens to your data at contract termination
- **SLAs:** Uptime guarantees, response times, patching commitments

### 4. Ongoing Monitoring

Risk does not end at contract signing:
- **Continuous monitoring:** Security rating services (BitSight, SecurityScorecard) for external posture assessment
- **Periodic reassessment:** Annual questionnaires for critical/high-tier vendors
- **Threat intelligence:** Monitor for vendor-related IOCs, breach disclosures, and CVEs in their products
- **Incident tracking:** Require vendors to report security incidents affecting your data or services
- **Certificate and audit report expiration:** Track SOC 2 report periods and ISO certification renewals

### 5. Offboarding

When a vendor relationship ends:
- Revoke all access immediately (credentials, VPN, API keys, physical badges)
- Confirm data return or certified destruction
- Remove network connectivity and firewall rules
- Update documentation and asset inventory
- Retain audit logs for the relationship period per retention policy

## Frameworks and Standards

- **NIST 800-161:** Supply chain risk management practices
- **ISO 27036:** Information security for supplier relationships
- **SIG (Standardized Information Gathering):** Shared Assessments questionnaire
- **CAIQ (Consensus Assessments Initiative Questionnaire):** Cloud Security Alliance tool for cloud providers

## SOC Relevance

SOC teams should monitor third-party network connections, VPN access, and API activity. Vendor-specific detection rules can identify anomalous behavior from service provider accounts (unusual hours, unexpected data access, large downloads). When a vendor breach is disclosed, the SOC should immediately assess exposure by reviewing access logs and network connections for the affected vendor's systems and credentials.
""",
    },
    {
        "title": "Business Continuity and Disaster Recovery Planning",
        "tags": ["governance", "bcdr", "disaster-recovery", "business-continuity", "resilience"],
        "content": r"""# Business Continuity and Disaster Recovery Planning

Business Continuity (BC) and Disaster Recovery (DR) planning ensures an organization can maintain critical operations during and after disruptive events. For security teams, BC/DR is both a responsibility (protecting the plan) and a capability (recovering from security incidents).

## Key Concepts and Metrics

**Recovery Time Objective (RTO):**
Maximum acceptable time to restore a system or process after disruption. An RTO of 4 hours means the business cannot tolerate more than 4 hours of downtime.

**Recovery Point Objective (RPO):**
Maximum acceptable data loss measured in time. An RPO of 1 hour means backups must be no more than 1 hour old — any data created after the last backup is lost.

**Maximum Tolerable Downtime (MTD):**
The absolute longest a business function can be unavailable before causing irreversible harm to the organization.

**Business Impact Analysis (BIA):**
The process of identifying critical business functions, their dependencies, and the impact of disruption at various time intervals.

## The BC/DR Planning Process

### 1. Business Impact Analysis

For each business function, determine:
- What systems, applications, and data does it depend on?
- What is the financial impact of downtime per hour/day?
- What is the reputational and regulatory impact?
- What is the MTD, RTO, and RPO?
- What are the upstream and downstream dependencies?

### 2. Risk Assessment

Identify threats that could cause disruption:
- **Natural:** Earthquake, flood, hurricane, fire
- **Technical:** Hardware failure, software bugs, network outage, data corruption
- **Human:** Human error, insider threat, key person dependency
- **Malicious:** Ransomware, DDoS, sabotage, supply chain attack
- **External:** Power grid failure, ISP outage, pandemic, civil unrest

### 3. Strategy Development

**Data protection strategies:**
- **Backup types:** Full, incremental, differential
- **Backup locations:** On-site (fast recovery), off-site (disaster protection), cloud (scalable)
- **3-2-1 rule:** 3 copies, 2 different media types, 1 off-site
- **Immutable backups:** Write-once storage to protect against ransomware encryption
- **Backup testing:** Regular restore tests to verify backup integrity and procedure accuracy

**System recovery strategies:**
- **Active-active:** Multiple sites running simultaneously (lowest RTO, highest cost)
- **Active-passive (hot standby):** Secondary site ready to take over within minutes
- **Warm standby:** Secondary site with infrastructure provisioned but not running production workloads
- **Cold site:** Empty facility with power and connectivity, requires hardware deployment (hours to days)
- **Cloud DR:** Replicate to cloud infrastructure, scale up on demand

### 4. Plan Documentation

A BC/DR plan should include:
- Roles and responsibilities (who declares a disaster, who leads recovery)
- Contact lists (internal teams, vendors, emergency services, regulators)
- Activation criteria (what constitutes a disaster vs. an operational incident)
- Recovery procedures (step-by-step for each critical system)
- Communication plan (internal notifications, customer/partner communications, media response)
- Workaround procedures (manual processes during system outage)

### 5. Testing and Exercises

| Test Type | Description | Frequency |
|---|---|---|
| Tabletop exercise | Walk through scenarios in a meeting | Quarterly |
| Functional test | Test specific recovery procedures | Semi-annually |
| Full-scale exercise | Simulate disaster and execute full recovery | Annually |
| Backup restore test | Verify backups can be restored successfully | Monthly |

### 6. Maintenance

- Review and update plans after organizational changes (mergers, new systems, staff changes)
- Incorporate lessons learned from actual incidents and exercises
- Ensure contact information remains current
- Align with evolving threat landscape (ransomware scenarios are now essential)

## Ransomware-Specific Considerations

Modern BC/DR must specifically address ransomware:
- **Immutable backups:** Attackers deliberately target backup systems
- **Offline / air-gapped backups:** At least one backup copy must be unreachable from the network
- **Backup encryption:** Encrypt backups with keys stored separately from the backup infrastructure
- **Recovery playbook:** Include steps for forensic investigation before restoration to avoid re-infection
- **Decision framework:** Criteria for paying vs. not paying ransom (legal, ethical, practical considerations)

## SOC Relevance

SOC teams are often the first to detect events that may trigger BC/DR activation (ransomware outbreak, major infrastructure compromise, DDoS attack). Analysts should know: the activation criteria for the BC/DR plan, the escalation path to declare a disaster, and their specific role during recovery operations. SOC infrastructure itself should be included in DR planning — if the SIEM is down during a disaster, detection capability is lost when it is needed most.
""",
    },
]

COLLECTIONS = [
    (
        "Cloud Security Fundamentals",
        "Shared responsibility, IAM, storage, VPC, logging, containers, serverless, and IaC security",
        CLOUD_SECURITY,
    ),
    (
        "SIEM & Security Analytics",
        "SIEM architecture, log onboarding, correlation rules, alert tuning, Sigma, queries, SOAR, and SOC metrics",
        SIEM_ANALYTICS,
    ),
    (
        "Security Governance & Compliance",
        "ISO 27001, NIST CSF, SOC 2, GDPR, PCI DSS, vulnerability management, TPRM, and BC/DR planning",
        GOVERNANCE,
    ),
]
