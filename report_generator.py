from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
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
    check_ids = [result['check_id'] for result in filtered_results]
    elements.append(Paragraph("Compliance Requirements", subtitle_style))
    for check_id in check_ids:
        check_info = CHECK_DESCRIPTIONS.get(check_id, {})
        elements.append(Paragraph(f"{check_id}: {check_info.get('title', '')}", subtitle_style))
        
        # 检查是否存在必要的键，避免KeyError
        if 'description' in check_info:    
            elements.append(Paragraph(f"Description: {check_info['description']}", normal_style))
            elements.append(Spacer(1, 0.1*inch))
        
        if 'remediation' in check_info:
            elements.append(Paragraph(f"Remediation: {check_info['remediation']}", normal_style))
        
        elements.append(Spacer(1, 0.25*inch))

    # Detailed Findings
    elements.append(Paragraph("Detailed Findings", subtitle_style))

    # 创建表格样式
    cell_style = ParagraphStyle(
        name='CellStyle',
        parent=normal_style,
        fontSize=9,
        leading=10
    )
    
    header_style = ParagraphStyle(
        name='HeaderStyle',
        parent=normal_style,
        fontSize=10,
        leading=12,
        fontName='Helvetica-Bold'
    )

    # 表头也改为Paragraph对象
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
        details = str(result.get('details', {}))

        # 将所有字符串转换为Paragraph对象
        row = [
            Paragraph(check_id, cell_style),
            Paragraph(check_title, cell_style),
            Paragraph(status, cell_style),
            Paragraph(details, cell_style)
        ]
        table_data.append(row)
    
    # Create table
    table = Table(table_data, repeatRows=1)
    
    # Table style
    table_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BACKGROUND', (0, 1), (-1, -1), colors.mistyrose)
    ])
    
    table.setStyle(table_style)
    elements.append(table)
    
    # Build PDF
    doc.build(elements)
    
    print(f"PDF Report generated for cluster {cluster_name}: {filename}")
    return filename
        
    