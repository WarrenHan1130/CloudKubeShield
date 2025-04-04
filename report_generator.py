from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime

# Description of each CIS check.
CHECK_DESCRIPTIONS = {
    "2.1.1": {
        "title": "Enable audit Logs",
        "description": "Enable control plane logs in Amazon EKS to capture API server requests, including audit, authenticator, controller manager, and scheduler logs. These logs, exported to CloudWatch, enhance security by detecting anomalies while ensuring persistent storage with minimal performance impact.",
        "remediation": "Enable all control plane log types in the EKS console under the cluster's 'Logging' configuration."
    },

    "2.1.2": {
        "title": "Ensure audit logs are collected and managed",
        "description": "Ensure that audit logs are collected and managed in accordance with the enterprise's audit log management process across all Kubernetes components.",
        "remediation": "Enable the audit logs in each worker node then transfer the logs to CloudWatch."
    },

    "3.1.1": {
        "title": "Ensure that the kubeconfig file permissions are set to 644 or more restrictive",
        "description": "If kubelet is running, and if it is configured by a kubeconfig file, ensure that the proxy kubeconfig file has permissions of 644 or more restrictive.",
        "remediation": "Run the command chmod 644 <kubeconfig file> (based on the file location on your system) on the each worker node."
    },

    "3.1.2": {
        "title": "Ensure that the kubelet kubeconfig file ownership is set to root:root",
        "description": "If kubelet is running, and if it is configured by a kubeconfig file, ensure that the proxy kubeconfig file has ownership of root:root.",
        "remediation": "Run the command chown root:root <kubeconfig file> (based on the file location on your system) on the each worker node."
    },

    "3.1.3": {
        "title": "Ensure that the kubelet kubeconfig file permissions are set to 644 or more restrictive",
        "description": "If kubelet is running, and if it is configured by a kubeconfig file, ensure that the proxy kubeconfig file has permissions of 644 or more restrictive.",
        "remediation": "Run the command chmod 644 <kubeconfig file> (based on the file location on your system) on the each worker node."
    },

    "3.1.4": {
        "title": "Ensure that the kubelet kubeconfig file ownership is set to root:root",
        "description": "If kubelet is running, and if it is configured by a kubeconfig file, ensure that the proxy kubeconfig file has ownership of root:root.",
        "remediation": "Run the command chown root:root <kubeconfig file> (based on the file location on your system) on the each worker node."
    },  

    "3.2.1": {
        "title": "Ensure that the API server is not enabled to authenticate with unauthenticated requests",
        "description": "Ensure that the API server is not enabled to authenticate with unauthenticated requests.",
        "remediation": "Run the command --anonymous-auth=false on the API server."
    },
    
    "3.2.2": {
        "title": "Ensure that the API server is configured to use the webhook authorization mode",
        "description": "Ensure that the API server is configured to use the webhook authorization mode.",
        "remediation": "Run the command --authorization-mode=Webhook on the API server."
    },

    "3.2.3": {
        "title": "Ensure that the x509 client certificate authentication is enabled for the API server",
        "description": "Ensure that the x509 client certificate authentication is enabled for the API server.",
        "remediation": "Run the command --client-ca-file=/path/to/ca.crt on the API server."
    },  

    "3.2.4": {
        "title": "Ensure that the read-only port is not enabled for the API server",
        "description": "Ensure that the read-only port is not enabled for the API server.",
        "remediation": "Run the command --read-only-port=0 on the API server."
    },      

    "3.2.5": {
        "title": "Ensure that the streaming connection idle timeout is set to 4 hours or less",
        "description": "Ensure that the streaming connection idle timeout is set to 4 hours or less.",
        "remediation": "Run the command --streaming-connection-idle-timeout=4h0m0s on the API server."
    },  

    "3.2.6": {
        "title": "Ensure that the makeIPTablesUtilChains is set to true",
        "description": "Ensure that the makeIPTablesUtilChains is set to true.",
        "remediation": "Run the command --make-iptables-util-chains=true on the API server."
    },    

    "3.2.7": {
        "title": "Ensure that the event record QPS is set to 5 or less",
        "description": "Ensure that the event record QPS is set to 5 or less.",
        "remediation": "Run the command --event-qps=5 on the API server."
    },    

    "3.2.8": {
        "title": "Ensure that the rotate certificates feature is enabled",
        "description": "Ensure that the rotate certificates feature is enabled.",
        "remediation": "Run the command --feature-gates=RotateKubeletServerCertificate=true on the API server."
    },      

    "3.2.9": {
        "title": "Ensure that the rotate certificates feature is enabled",
        "description": "Ensure that the rotate certificates feature is enabled.",
        "remediation": "Run the command --feature-gates=RotateKubeletServerCertificate=true on the API server."
    },          
    "4.1.1": {
        "title": "Ensure that the cluster-admin role is only used where required",
        "description": "The cluster-admin role grants full administrative access to the cluster. It should only be assigned where absolutely necessary to minimize the risk of privilege escalation.",
        "remediation": "Review all ClusterRoleBindings associated with the cluster-admin role and remove unnecessary bindings. Run the command: kubectl delete clusterrolebinding [name] to remove specific bindings."
    },
    "4.1.2": {
        "title": "Minimize access to secrets",
        "description": "Restrict access to Kubernetes secrets to prevent unauthorized disclosure of sensitive credentials and API tokens.",
        "remediation": "Review all roles and cluster roles granting access to secrets. Update RBAC policies to minimize exposure using kubectl edit clusterrole [name] or kubectl edit role [name]."
    },
    "4.1.3": {
        "title": "Minimize wildcard use in Roles and ClusterRoles",
        "description": "Avoid using wildcards ('*') in Kubernetes RBAC permissions to ensure fine-grained access control and reduce unintended privilege escalation.",
        "remediation": "Identify roles and cluster roles using wildcards by running kubectl get clusterroles -o yaml and kubectl get roles --all-namespaces -o yaml, then modify them to explicitly define required permissions."
    },
    "4.1.4": {
        "title": "Minimize access to create pods",
        "description": "Restrict the ability to create pods to prevent unauthorized deployment of workloads that could lead to privilege escalation.",
        "remediation": "Review RBAC policies that grant 'create' permissions on pods. Remove or limit access using kubectl edit role [name] or kubectl edit clusterrole [name]."
    },
    "4.1.5": {
        "title": "Ensure that default service accounts are not actively used",
        "description": "The default service account in each namespace should not be actively used to prevent accidental privilege escalation.",
        "remediation": "Set automountServiceAccountToken: false for the default service account in each namespace using kubectl patch serviceaccount default -n [namespace] -p '{\"automountServiceAccountToken\": false}'."
    },
    "4.1.6": {
        "title": "Ensure that Service Account Tokens are only mounted where necessary",
        "description": "Service account tokens should not be automatically mounted in pods unless explicitly required to reduce attack surface.",
        "remediation": "Ensure automountServiceAccountToken is set to false for all service accounts and pods that do not require API access by running kubectl patch serviceaccount [name] -p '{\"automountServiceAccountToken\": false}'."
    },
    "4.1.7": {
        "title": "Ensure that the Cluster Access Manager API is used instead of aws-auth ConfigMap",
        "description": "Amazon EKS clusters should use the Cluster Access Manager API for authentication instead of the aws-auth ConfigMap to improve security and auditability.",
        "remediation": "Check the authentication mode using aws eks describe-cluster --name [CLUSTER_NAME] --query \"cluster.accessConfig\" --output json. If set to CONFIG_MAP, migrate to EKS API authentication."
    },
    "4.1.8": {
        "title": "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster",
        "description": "The bind, impersonate, and escalate permissions allow users to increase their privileges and should be restricted to minimize security risks.",
        "remediation": "Review roles and cluster roles granting these permissions using kubectl get clusterroles -o yaml and kubectl get roles --all-namespaces -o yaml, then modify them to remove unnecessary privileges."
    },
     "4.1.9": {
        "title": "Restrict usage of hostPath volumes in cluster workloads",
        "description": "Restrict usage of hostPath volumes in cluster workloads",
        "remediation": "Review and restrict configurations to enforce: restrict usage of hostpath volumes in cluster workloads."
    },
    "4.2.1": {
        "title": "Minimize the admission of privileged containers",
        "description": "Minimize the admission of privileged containers",
        "remediation": "Review and restrict configurations to enforce: minimize the admission of privileged containers."
    },
    "4.2.2": {
        "title": "Minimize the admission of containers wishing to share the host process ID namespace",
        "description": "Minimize the admission of containers wishing to share the host process ID namespace",
        "remediation": "Review and restrict configurations to enforce: minimize the admission of containers wishing to share the host process id namespace."
    },
    "4.2.3": {
        "title": "Minimize the admission of containers wishing to share the host IPC namespace",
        "description": "Minimize the admission of containers wishing to share the host IPC namespace",
        "remediation": "Review and restrict configurations to enforce: minimize the admission of containers wishing to share the host ipc namespace."
    },
    "4.2.4": {
        "title": "Minimize the admission of containers wishing to share the host network namespace",
        "description": "Minimize the admission of containers wishing to share the host network namespace",
        "remediation": "Review and restrict configurations to enforce: minimize the admission of containers wishing to share the host network namespace."
    },
    "4.2.5": {
        "title": "Minimize the admission of containers with allowPrivilegeEscalation",
        "description": "Minimize the admission of containers with allowPrivilegeEscalation",
        "remediation": "Review and restrict configurations to enforce: minimize the admission of containers with allowprivilegeescalation."
    },
    "4.3.1": {
        "title": "Ensure CNI plugin supports network policies",
        "description": "Ensure CNI plugin supports network policies",
        "remediation": "Review and configure CNI plugin to support Kubernetes network policies."
    },
    "4.3.2": {
        "title": "Ensure that all Namespaces have Network Policies defined",
        "description": "Ensure that all Namespaces have Network Policies defined",
        "remediation": "Create appropriate Network Policies in each namespace to restrict traffic as needed."
    },
    "4.4.1": {
        "title": "Prefer using secrets as files over secrets as environment variables",
        "description": "Prefer using secrets as files over secrets as environment variables",
        "remediation": "Modify workloads to mount secrets as files rather than using environment variables."
    },
    "4.4.2": {
        "title": "Consider external secret storage",
        "description": "Consider external secret storage",
        "remediation": "Integrate Kubernetes with external secret management systems like AWS Secrets Manager or HashiCorp Vault."
    },
    "4.5.1": {
        "title": "Create administrative boundaries between resources using namespaces",
        "description": "Create administrative boundaries between resources using namespaces",
        "remediation": "Define and enforce resource isolation using Kubernetes namespaces for different teams or applications."
    },
    "4.5.2": {
        "title": "The default namespace should not be used",
        "description": "The default namespace should not be used",
        "remediation": "Configure workloads to use dedicated namespaces instead of the default namespace."
    }

}

def generate_pdf_report(results, filename, cluster_name, include_compliant=True):

    title="AWS Compliance Report"

    # Filter results if only non-compliant items are needed
    if not include_compliant:
        filtered_results = [r for r in results if not r['compliant']]
    else:
        filtered_results = results
    
    if not filtered_results and not include_compliant:
        print("No non-compliant resources found. Report not generated.")
        return None

    # Create a new PDF document
    doc = SimpleDocTemplate(
        filename,
        pagesize=landscape(letter),
        rightMargin=0.5*inch,
        leftMargin=0.5*inch,
        topMargin=0.5*inch,
        bottomMargin=0.5*inch
    )

    # Define styles
    styles = getSampleStyleSheet()
    title_style = styles["Heading1"]
    subtitle_style = styles["Heading2"]
    normal_style = styles["Normal"]

    cell_style = ParagraphStyle(
        name='CellStyle',
        parent=normal_style,
        fontSize=9,
        leading=10,
        wordWrap='CJK'  
    )

    header_style = ParagraphStyle(
        name='HeaderStyle',
        parent=normal_style,
        fontSize=10,
        leading=12,
        fontName='Helvetica-Bold'
    )

    # Create report elements
    elements = []
    
    # Title
    report_title = f"EKS Security Compliance Report - {cluster_name}"
    elements.append(Paragraph(report_title, title_style))
    elements.append(Spacer(1, 0.25*inch))
    
    total_checks = len(results)
    non_compliant_checks = sum(1 for r in results if not r['compliant'])

    # Cluster Information
    elements.append(Paragraph("Cluster Information", subtitle_style))
    elements.append(Paragraph(f"Cluster Name: {cluster_name}", normal_style))
    elements.append(Paragraph(f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Spacer(1, 0.25*inch))

    # Summary
    elements.append(Paragraph(f"Total Resources Checked: {total_checks}", normal_style))
    elements.append(Paragraph(f"Non-Compliant Resources: {non_compliant_checks}", normal_style))
    elements.append(Paragraph(f"Compliance Rate: {((total_checks - non_compliant_checks) / total_checks * 100) if total_checks > 0 else 0:.2f}%", normal_style))
    elements.append(Spacer(1, 0.5*inch))

    # Compliance Requirements
    check_ids = [cid for cid in CHECK_DESCRIPTIONS if cid in {r['check_id'] for r in filtered_results}]
    elements.append(Paragraph("Compliance Requirements", subtitle_style))
    for check_id in check_ids:
        check_info = CHECK_DESCRIPTIONS.get(check_id, {})
        elements.append(Paragraph(f"{check_id}: {check_info.get('title', '')}", subtitle_style))
        
        if 'description' in check_info:    
            elements.append(Paragraph(f"Description: {check_info['description']}", normal_style))
            elements.append(Spacer(1, 0.1*inch))
        
        if 'remediation' in check_info:
            elements.append(Paragraph(f"Remediation: {check_info['remediation']}", normal_style))
        
        elements.append(Spacer(1, 0.25*inch))

    # Detailed Findings
    elements.append(Paragraph("Detailed Findings", subtitle_style))

    # Set a maximum width for each column to prevent overflow
    col_widths = [1.2*inch, 2*inch, 1.2*inch, 4*inch]  # Adjust these values based on your needs

    table_data = [
        [
            Paragraph("Check ID", header_style),
            Paragraph("Check Title", header_style),
            Paragraph("Status", header_style),
            Paragraph("Details", header_style)
        ]
    ]

    for result in filtered_results:
        check_id = result['check_id']
        check_title = result.get('title', '')
        status = "Compliant" if result['compliant'] else "Non-Compliant"
        
        # Limit the details length and ensure it's a string
        details = str(result.get('details', {}))
        if len(details) > 500:  # Limit details to prevent overflow
            details = details[:497] + "..."
        
        row = [
            Paragraph(check_id, cell_style),
            Paragraph(check_title, cell_style),
            Paragraph(status, cell_style),
            Paragraph(details, cell_style)
        ]
        table_data.append(row)
    
    # Create table with specified column widths
    table = Table(table_data, repeatRows=1, colWidths=col_widths)
    
    # Table style with improved row separation for readability
    table_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),  # Changed from MIDDLE to TOP
        ('ROWHEIGHT', (0, 0), (-1, -1), 0.4*inch),  # Set a maximum row height
    ])
    
    # Color alternating rows for better readability
    for i in range(1, len(table_data)):
        if not filtered_results[i-1]['compliant']:
            bc = colors.mistyrose
        else:
            bc = colors.white if i % 2 == 0 else colors.lightcyan
        table_style.add('BACKGROUND', (0, i), (-1, i), bc)
    
    table.setStyle(table_style)
    elements.append(table)
    
    # Build PDF
    doc.build(elements)
    
    print(f"PDF Report generated for cluster {cluster_name}: {filename}")
    return filename
        
    