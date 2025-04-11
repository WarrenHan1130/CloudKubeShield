import traceback
import boto3
import kubernetes
import tempfile
import base64
import subprocess
import os
import argparse
import sys
import json
import scan
import report_generator
from datetime import datetime
import configparser
import remediation

def interactive_cli():
    print("Welcome to AWS Tool")
    print("Type 'help' to see available commands, type 'exit' to quit")
    
    while True:
        command = input("\naws-tool> ").strip()
        
        if command.lower() == 'exit':
            print("Thank you for using AWS Tool. Goodbye!")
            break

        elif command.lower() == 'help':
            print("Available commands:")
            print("  configure - Configure AWS credentials")
            print("  install - Install all required Python dependencies")
            print("  list-profiles - List available AWS profiles")
            print("  test-connection - Test AWS connection")
            print("  help - Display this help information")
            print("  exit - Exit the program")
            print("  k8s - Scan and remediate Kubernetes clusters")
            print("  skip-checks - Configure which checks to skip")
            print("  enable-optional-fix - Enable optional fixes")

        elif command.lower() == 'configure':
            profile = input("Profile name (leave empty for default): ").strip()
            configure_aws_profile(profile if profile else None)

        elif command.lower() == 'k8s':
            profile = input("Profile name (leave empty for default): ").strip()
            session = create_aws_session(profile if profile else None)
            skip_checks = load_skip_config()
            enable_fix_ids = load_enable_fix_config()
            create_k8s_session(session, skip_checks=skip_checks, enable_fix_ids=enable_fix_ids) 
        
        elif command.lower() == 'install':
            print("Installing required dependencies...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
                print("Dependencies installed successfully.")
            except subprocess.CalledProcessError:
                print("Failed to install dependencies.")

        elif command.lower() == 'list-profiles':
            list_profiles()
        
        elif command.lower() == 'test-connection':
            profile = input("Profile name (leave empty for default): ").strip()
            test_connection(profile if profile else None)

        elif command.lower() == 'skip-checks':
            skip_checks = select_checks_to_skip()
            save_skip_config(skip_checks)
            print(f"Skipping checks: {', '.join([str(num) for num in skip_checks])}")

        elif command.lower() == 'enable-optional-fix':
            enable_fix_ids = select_fix_enable_checks()
            save_enable_fix_config(enable_fix_ids)
            print(f"Enabling fixes for checks: {', '.join([str(num) for num in enable_fix_ids])}")

        else:
            print(f"Unknown command: {command}")

def test_connection(profile=None):
    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        print("AWS Connection Successful!")
        print(f"Account: {identity['Account']}")
        print(f"User ID: {identity['UserId']}")
        print(f"ARN: {identity['Arn']}")
    except Exception as e:
        print("AWS Connection Failed.")
        print(f"Error: {e}")

def list_profiles():
    config_path = os.path.expanduser("~/.aws/credentials")
    if not os.path.exists(config_path):
        print("No AWS credentials file found.")
        return

    config = configparser.ConfigParser()
    config.read(config_path)

    print("Available AWS profiles:")
    for section in config.sections():
        print(f"  - {section}")

def get_all_aws_profiles():
    config_path = os.path.expanduser("~/.aws/credentials")
    if not os.path.exists(config_path):
        return []
    config = configparser.ConfigParser()
    config.read(config_path)
    return config.sections()

def get_cis_remediation():
    return [
        {"id": "4.1.1", "number": 1, "name": "Ensure that the cluster-admin role is only used where required", "enable_fix": True},
        {"id": "4.1.5", "number": 2, "name": "Ensure that default service accounts are not actively used.", "enable_fix": True},
        {"id": "4.2.1", "number": 3, "name": "Minimize the admission of privileged containers", "enable_fix": True},
        {"id": "4.3.2", "number": 4, "name": "Ensure that all Namespaces have Network Policies defined", "enable_fix": True},
        {"id": "4.5.2", "number": 5, "name": "The default namespace should not be used", "enable_fix": True},
        {"id": "5.2.1", "number": 6, "name": "Prefer using dedicated EKS Service Accounts", "enable_fix": True},
        {"id": "5.4.1", "number": 7, "name": "Restrict Access to the Control Plane Endpoint", "enable_fix": True},
        {"id": "5.4.2", "number": 8, "name": "Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled", "enable_fix": True},
        {"id": "5.4.3", "number": 9, "name": "Ensure clusters are created with Private Nodes", "enable_fix": True},
    ]

def get_cis_checks():
   
    return [
        {"id": "2.1.1", "number": 1, "name": "Enable audit Logs"},
        {"id": "2.1.2", "number": 2, "name": "Ensure audit logs are collected and managed"},
        {"id": "3.1.1", "number": 3, "name": "Ensure that the kubeconfig file permissions are set to 644 or more restrictive."},
        {"id": "3.1.2", "number": 4, "name": "Ensure that the kubelet kubeconfig file ownership is set to root:root"},
        {"id": "3.1.3", "number": 5, "name": "Ensure that the kubelet kubeconfig file permissions are set to 644 or more restrictive"},
        {"id": "3.1.4", "number": 6, "name": "Ensure that the kubelet config file permissions are set to 644 or more restrictive"},
        {"id": "3.2.1", "number": 7, "name": "Ensure that the Anonymous Auth is Not Enabled"},
        {"id": "3.2.2", "number": 8, "name": "Ensure that the --authorization-mode argument is not set to AlwaysAllow"},
        {"id": "3.2.3", "number": 9, "name": "Ensure that a Client CA File is Configured"},
        {"id": "3.2.4", "number": 10, "name": "Ensure that the --read-only-port is disabled"},
        {"id": "3.2.5", "number": 11, "name": "Ensure that the --streaming-connection-idle-timeout argument is not set to 0"},
        {"id": "3.2.6", "number": 12, "name": "Ensure that the --make-iptables-util-chains argument is set to true"},
        {"id": "3.2.7", "number": 13, "name": "Ensure that the --eventRecordQPS argument is set to 0 or a level which ensures appropriate event capture"},
        {"id": "3.2.8", "number": 14, "name": "Ensure that the --rotate-certificates argument is not present or is set to true"},
        {"id": "3.2.9", "number": 15, "name": "Ensure that the RotateKubeletServerCertificate feature gate is enabled"},
        {"id": "4.1.1", "number": 16, "name": "Ensure that the cluster-admin role is only used where required"},
        {"id": "4.1.2", "number": 17, "name": "Ensure that access to Kubernetes secrets is restricted"},
        {"id": "4.1.3", "number": 18, "name": "Minimize wildcard use in Roles and ClusterRoles"},
        {"id": "4.1.4", "number": 19, "name": "Minimize access to create pods"},
        {"id": "4.1.5", "number": 20, "name": "Ensure that default service accounts are not actively used."},
        {"id": "4.1.6", "number": 21, "name": "Ensure that Service Account Tokens are only mounted where necessary"},
        {"id": "4.1.7", "number": 22, "name": "Cluster Access Manager API to streamline and enhance the management of access controls within EKS clusters"},
        {"id": "4.1.8", "number": 23, "name": "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster"},
        {"id": "4.2.1", "number": 24, "name": "Minimize the admission of privileged containers"},
        {"id": "4.2.2", "number": 25, "name": "Minimize the admission of containers wishing to share the host process ID namespace"},
        {"id": "4.2.3", "number": 26, "name": "Minimize the admission of containers wishing to share the host IPC namespace"},
        {"id": "4.2.4", "number": 27, "name": "Minimize the admission of containers wishing to share the host network namespace"},
        {"id": "4.2.5", "number": 28, "name": "Minimize the admission of containers with allowPrivilegeEscalation"},
        {"id": "4.3.1", "number": 29, "name": "Ensure CNI plugin supports network policies"},
        {"id": "4.3.2", "number": 30, "name": "Ensure that all Namespaces have Network Policies defined"},
        {"id": "4.4.1", "number": 31, "name": "Prefer using secrets as files over secrets as environment variables"},
        {"id": "4.4.2", "number": 32, "name": "Consider external secret storage"},
        {"id": "4.5.1", "number": 33, "name": "Create administrative boundaries between resources using namespaces"},
        {"id": "4.5.2", "number": 34, "name": "The default namespace should not be used"},
        {"id": "5.1.1", "number": 35, "name": "5.1.1 Ensure Image Vulnerability Scanning using Amazon ECR image scanning or a third party provider"},
        {"id": "5.1.2", "number": 36, "name": "Minimize user access to Amazon ECR"},
        {"id": "5.1.3", "number": 37, "name": "Minimize cluster access to read-only for Amazon ECR"},
        {"id": "5.1.4", "number": 38, "name": "Minimize Container Registries to only those approved"},
        {"id": "5.2.1", "number": 39, "name": "Prefer using dedicated EKS Service Accounts"},
        {"id": "5.3.1", "number": 40, "name": "Ensure Kubernetes Secrets are encrypted using Customer Master Keys (CMKs) managed in AWS KMS"},
        {"id": "5.4.1", "number": 41, "name": "Restrict Access to the Control Plane Endpoint"},
        {"id": "5.4.2", "number": 42, "name": "Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled"},
        {"id": "5.4.3", "number": 43, "name": "Ensure clusters are created with Private Nodes"},
        {"id": "5.4.4", "number": 44, "name": "Ensure Network Policy is Enabled and set as appropriate"},
        {"id": "5.4.5", "number": 45, "name": "Encrypt traffic to HTTPS load balancers with TLS certificates"},
        {"id": "5.5.1", "number": 46, "name": "Manage Kubernetes RBAC users with AWS IAM Authenticator for Kubernetes or Upgrade to AWS CLI v1.16.156 or greater"},
    ]

def select_fix_enable_checks():
    checks = get_cis_remediation()
    print("Any fix below is optional and may cause issues with the cluster. Use at your own risk.")
    print("\nThese checks support optional remediation (enable_fix=False by default):")
    
    for check in checks:
        print(f"{check['number']}. CIS {check['id']}: {check['name']}")

    input_ids = input("\nEnter the numbers to enable remediation (comma separated, or press Enter to skip all): ").strip()
    enable_fix_ids = []

    if input_ids:
        try:
            selected_numbers = [int(i.strip()) for i in input_ids.split(",") if i.strip().isdigit()]
            enable_fix_ids = [check["id"] for check in checks if check["number"] in selected_numbers]
        except ValueError:
            print("Invalid input. No enable_fix will be set to True.")
    
    return enable_fix_ids

def save_enable_fix_config(enable_fix_ids):
    CONFIG_FILE = "eks_remediation_config.json"
    with open(CONFIG_FILE, 'w') as f:
        json.dump({"enable_fix_ids": enable_fix_ids}, f)
    print(f"Configuration saved to {CONFIG_FILE}")

def load_enable_fix_config():
    CONFIG_FILE = "eks_remediation_config.json"
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            return config.get("enable_fix_ids", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def select_checks_to_skip():
    checks = get_cis_checks()
    
    print("\nAvailable CIS Checks:")
    for check in checks:
        print(f"{check['number']}. CIS {check['id']}: {check['name']}")
    
    skip_input = input("\nEnter the numbers of checks you want to skip (comma separated, e.g. '1,3,5'): ")
    
    skip_numbers = []
    if skip_input.strip():
        try:
            skip_numbers = [int(x.strip()) for x in skip_input.split(',') if x.strip()]
        except ValueError:
            print("Invalid input. No checks will be skipped.")
    
    return skip_numbers


def save_skip_config(skip_checks):
    CONFIG_FILE = "eks_scanner_config.json"
    with open(CONFIG_FILE, 'w') as f:
        json.dump({"skip_checks": skip_checks}, f)
    print(f"Configuration saved to {CONFIG_FILE}")

def load_skip_config():
    CONFIG_FILE = "eks_scanner_config.json"
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            return config.get("skip_checks", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def configure_aws_profile(profile_name=None):

    cmd = ['aws', 'configure']
    
    if profile_name:
        cmd.extend(['--profile', profile_name])
    
    print(f"\nStarting AWS configuration for {'profile ' + profile_name if profile_name else 'default profile'}")
    print("Please enter your AWS credentials and settings as prompted\n")
    
    try:
        # Run aws configure command
        subprocess.run(cmd, check=True)
        
        # Check if configuration was successful
        aws_dir = os.path.expanduser("~/.aws")
        credentials_path = os.path.join(aws_dir, "credentials")
        
        if os.path.exists(credentials_path):
            print(f"\nAWS {'profile ' + profile_name if profile_name else 'default profile'} configured successfully!")
            print(f"Credentials saved at: {credentials_path}")
        else:
            print("\nConfiguration process may not have completed, credentials file not found.")
            
    except subprocess.CalledProcessError as e:
        print(f"\nConfiguration failed: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print("\nError: AWS CLI not found. Please make sure AWS CLI is installed and added to PATH.")
        print("Installation instructions: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html")
        sys.exit(1)

def create_aws_session(profile_name=None):

    try:
        session = boto3.Session(profile_name=profile_name)
        return session
    except Exception as e:
        print(f"Error creating session with '{profile_name}' Specific error is: {e}")
        return None
            
def create_k8s_session(session, profile, skip_checks=None, enable_fix_ids=None):

    try:
        eks_client = session.client("eks")
        region = eks_client._client_config.region_name
        print(f"Region: {region}")
        cluster_names = []
         #list all clusters in the account

        checks = get_cis_checks()
        if skip_checks is None:
            skip_checks = []

        if skip_checks:
            print(f"Skipping checks: {', '.join([str(num) for num in skip_checks])}")

        skip_check_ids = [check["id"] for check in checks if check["number"] in skip_checks]
        
        response = eks_client.list_clusters()
        if 'clusters' in response:
            if response['clusters']:
                cluster_names = response['clusters']
                print("Available EKS clusters:")
                for i, cluster in enumerate(cluster_names, 1):
                    print(f"{i}. {cluster}")
            else:
                print("No EKS clusters found")
        else:
            print("Do not have permission to access EKS")

        if cluster_names:
            for cluster_name in cluster_names:
                print(f"Scanning cluster: {cluster_name}")
                #get token for the cluster
                result = subprocess.run(f"aws eks get-token --cluster-name {cluster_name} --profile {profile}", shell=True, capture_output=True, text=True)
                token_data = json.loads(result.stdout)
                token = token_data['status']['token']

                # Get detailed information about the specified cluster
                cluster_data = eks_client.describe_cluster(name=cluster_name)['cluster']

                # Extract the cluster's Certificate Authority (CA) data for SSL/TLS verification
                cluster_cert = cluster_data['certificateAuthority']['data']

                # Get the cluster API server endpoint URL
                cluster_endpoint = cluster_data['endpoint']

                # Create a temporary file to store the certificate data
                cafile = tempfile.NamedTemporaryFile(delete=False)

                # Get the base64 encoded certificate data
                cadata_b64 = cluster_cert

                # Decode the base64 certificate data to binary format
                cadata = base64.b64decode(cadata_b64)

                # Write the decoded certificate data to the temporary file
                cafile.write(cadata)
                cafile.flush()

                # Create a Kubernetes configuration object, setting:
                # - The cluster API endpoint
                # - Authentication token (using Bearer token authentication)
                kconfig = kubernetes.config.kube_config.Configuration(
                host=cluster_endpoint, 
                api_key={'authorization': 'Bearer ' + token})
                
                # Set the SSL certificate path to verify secure connection to the cluster API server
                kconfig.ssl_ca_cert = cafile.name if cafile.name else ""

                results = []
                scan_results = {}
                
                scan_map = {
                "2.1.1": lambda: scan.cis_2_1_1(cluster_data),
                "2.1.2": lambda: scan.cis_2_1_2(kconfig, cluster_name, region, profile),
                "3.1.1": lambda: scan.cis_3_1_1(kconfig, cluster_name, region, profile),
                "3.1.2": lambda: scan.cis_3_1_2(kconfig, cluster_name, region, profile),
                "3.1.3": lambda: scan.cis_3_1_3(kconfig, cluster_name, region, profile),
                "3.1.4": lambda: scan.cis_3_1_4(kconfig, cluster_name, region, profile),
                "3.2.1": lambda: scan.cis_3_2_1(kconfig, cluster_name, region, profile),
                "3.2.2": lambda: scan.cis_3_2_2(kconfig, cluster_name, region, profile),
                "3.2.3": lambda: scan.cis_3_2_3(kconfig, cluster_name, region, profile),
                "3.2.4": lambda: scan.cis_3_2_4(kconfig, cluster_name, region, session),
                "3.2.5": lambda: scan.cis_3_2_5(kconfig, cluster_name, region, profile),
                "3.2.6": lambda: scan.cis_3_2_6(kconfig, cluster_name, region, profile),
                "3.2.7": lambda: scan.cis_3_2_7(kconfig, cluster_name, region, session),
                "3.2.8": lambda: scan.cis_3_2_8(kconfig, cluster_name, region, session),
                "3.2.9": lambda: scan.cis_3_2_9(kconfig, cluster_name, region, profile),
                "4.1.1": lambda: scan.cis_4_1_1(kconfig, cluster_name),
                "4.1.2": lambda: scan.cis_4_1_2(kconfig, cluster_name),
                "4.1.3": lambda: scan.cis_4_1_3(kconfig, cluster_name),
                "4.1.4": lambda: scan.cis_4_1_4(kconfig, cluster_name),
                "4.1.5": lambda: scan.cis_4_1_5(kconfig, cluster_name),
                "4.1.6": lambda: scan.cis_4_1_6(kconfig, cluster_name),
                "4.1.7": lambda: scan.cis_4_1_7(cluster_name, region, session),
                "4.1.8": lambda: scan.cis_4_1_8(kconfig, cluster_name),
                "4.2.1": lambda: scan.cis_4_2_1(kconfig, cluster_name),
                "4.2.2": lambda: scan.cis_4_2_2(kconfig, cluster_name),
                "4.2.3": lambda: scan.cis_4_2_3(kconfig, cluster_name),
                "4.2.4": lambda: scan.cis_4_2_4(kconfig, cluster_name),
                "4.2.5": lambda: scan.cis_4_2_5(kconfig, cluster_name),
                "4.3.1": lambda: scan.cis_4_3_1(cluster_name, region, profile),
                "4.3.2": lambda: scan.cis_4_3_2(cluster_name, region, profile),
                "4.4.1": lambda: scan.cis_4_4_1(cluster_name, region, profile),
                "4.4.2": lambda: scan.cis_4_4_2(cluster_name),
                "4.5.1": lambda: scan.cis_4_5_1(cluster_name, region, profile),
                "4.5.2": lambda: scan.cis_4_5_2(cluster_name, region, profile),
                "5.1.1": lambda: scan.cis_5_1_1(session, cluster_name),
                "5.1.2": lambda: scan.cis_5_1_2(session),
                "5.1.3": lambda: scan.cis_5_1_3(session, cluster_name),
                "5.1.4": lambda: scan.cis_5_1_4(kconfig, cluster_name),
                "5.2.1": lambda: scan.cis_5_2_1(kconfig, cluster_name),
                "5.3.1": lambda: scan.cis_5_3_1(session, cluster_name),
                "5.4.1": lambda: scan.cis_5_4_1(session, cluster_name),
                "5.4.2": lambda: scan.cis_5_4_2(session, cluster_name),
                "5.4.3": lambda: scan.cis_5_4_3(session, cluster_name),
                "5.4.4": lambda: scan.cis_5_4_4(session, cluster_name),
                "5.4.5": lambda: scan.cis_5_4_5(kconfig, cluster_name),
                "5.5.1": lambda: scan.cis_5_5_1(kconfig, cluster_name)
                }

                for check in checks:
                    check_id = check["id"]
                    if check_id not in skip_check_ids:
                        check_number = check["number"]
                        check_name = check["name"]
                        print(f"Running check {check_number}. CIS {check_id}: {check_name}")
                        result = scan_map[check_id]()
                        scan_results[check_id] = result
                        results.append(result)
                    else:
                        print(f"Skipping check {check['number']}. CIS {check_id}")
            
                report_filename = f"compliance_report_{cluster_name}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pdf"
                report_generator.generate_pdf_report(results, report_filename, cluster_name, include_compliant=True)

                remediation_map = {
                "2.1.1": lambda result: remediation.remediate_cis_2_1_1(eks_client, cluster_name) if not result['compliant'] else None,
                "3.1.1": lambda result: remediation.remediate_cis_3_1_1(cluster_name, region, result['details'], profile) if not result['compliant'] else None,
                "3.1.2": lambda result: remediation.remediate_cis_3_1_2(cluster_name, region, result['details'], profile) if not result['compliant'] else None,
                "3.1.3": lambda result: remediation.remediate_cis_3_1_3(cluster_name, region, result['details'], profile) if not result['compliant'] else None,
                "3.1.4": lambda result: remediation.remediate_cis_3_1_4(cluster_name, region, result['details'], profile) if not result['compliant'] else None,
                "3.2.1": lambda result: remediation.remediate_cis_3_2_1(region, result['details'], session) if not result['compliant'] else None,
                "3.2.2": lambda result: remediation.remediate_cis_3_2_2(region, result['details'], session) if not result['compliant'] else None,
                "3.2.3": lambda result: remediation.remediate_cis_3_2_3(region, result['details'], session) if not result['compliant'] else None,
                "3.2.4": lambda result: remediation.remediate_cis_3_2_4(region, result['details'], session) if not result['compliant'] else None,
                "3.2.5": lambda result: remediation.remediate_cis_3_2_5(region, result['details'], session) if not result['compliant'] else None,
                "3.2.6": lambda result: remediation.remediate_cis_3_2_6(region, result['details'], session) if not result['compliant'] else None,
                "3.2.7": lambda result: remediation.remediate_cis_3_2_7(region, result['details'], session) if not result['compliant'] else None,
                "3.2.8": lambda result: remediation.remediate_cis_3_2_8(region, result['details'], session) if not result['compliant'] else None,
                "3.2.9": lambda result: remediation.remediate_cis_3_2_9(region, result['details'], session) if not result['compliant'] else None,
                "4.1.1": lambda result: remediation.remediate_cis_4_1_1(result['details'], enable_fix=("4.1.1" in enable_fix_ids)) if not result['compliant'] else None,
                "4.1.2": lambda result: remediation.remediate_cis_4_1_2(cluster_name) if not result['compliant'] else None,
                "4.1.3": lambda result: remediation.remediate_cis_4_1_3(cluster_name) if not result['compliant'] else None,
                "4.1.4": lambda result: remediation.remediate_cis_4_1_4(cluster_name) if not result['compliant'] else None,
                "4.1.5": lambda result: remediation.remediate_cis_4_1_5(enable_fix=("4.1.5" in enable_fix_ids)) if not result['compliant'] else None,
                "4.1.6": lambda result: remediation.remediate_cis_4_1_6(cluster_name) if not result['compliant'] else None,
                "4.1.7": lambda result: remediation.remediate_cis_4_1_7(cluster_name) if not result['compliant'] else None,
                "4.1.8": lambda result: remediation.remediate_cis_4_1_8(cluster_name) if not result['compliant'] else None,
                "4.2.1": lambda result: remediation.remediate_cis_4_2_x(cluster_name, result['details'], enable_fix=("4.2.1" in enable_fix_ids)) if not result['compliant'] else None,
                "4.3.1": lambda result: remediation.remediate_cis_4_3_1(cluster_name, region, profile) if not result['compliant'] else None,
                "4.3.2": lambda result: remediation.remediate_cis_4_3_2(cluster_name, region, result['details'], profile, enable_fix=("4.3.2" in enable_fix_ids)) if not result['compliant'] else None,
                "4.4.1": lambda result: remediation.remediate_cis_4_4_1(cluster_name) if not result['compliant'] else None,
                "4.5.1": lambda result: remediation.remediate_cis_4_5_1(cluster_name) if not result['compliant'] else None,
                "4.5.2": lambda result: remediation.remediate_cis_4_5_2(cluster_name, region, result['details'], profile, enable_fix=("4.5.2" in enable_fix_ids)) if not result['compliant'] else None,
                "5.1.1": lambda result: remediation.remediate_5_1_1(session, result['details']) if not result['compliant'] else None,
                "5.1.2": lambda result: remediation.remediate_cis_5_1_2(cluster_name) if not result['compliant'] else None,
                "5.1.3": lambda result: remediation.remediate_cis_5_1_3(cluster_name) if not result['compliant'] else None,
                "5.1.4": lambda result: remediation.remediate_cis_5_1_4(cluster_name) if not result['compliant'] else None,
                "5.2.1": lambda result: remediation.remediate_5_2_1(kconfig, result['details'], enable_fix=("5.2.1" in enable_fix_ids)) if not result['compliant'] else None,
                "5.3.1": lambda result: remediation.remediate_cis_5_3_1(cluster_name) if not result['compliant'] else None,
                "5.4.1": lambda result: remediation.remediate_5_4_1(session, cluster_name, enable_fix=("5.4.1" in enable_fix_ids)) if not result['compliant'] else None,
                "5.4.2": lambda result: remediation.remediate_5_4_2(session, cluster_name, my_ip_cidr="", enable_fix=("5.4.2" in enable_fix_ids)) if not result['compliant'] else None,
                "5.4.3": lambda result: remediation.remediate_5_4_3(session, cluster_name, my_ip_cidr="", enable_fix=("5.4.3" in enable_fix_ids)) if not result['compliant'] else None,
                "5.4.4": lambda result: remediation.remediate_5_4_4(session, cluster_name) if not result['compliant'] else None,
                "5.4.5": lambda result: remediation.remediate_cis_5_4_5(cluster_name) if not result['compliant'] else None,
                "5.5.1": lambda result: remediation.remediate_cis_5_5_1(cluster_name) if not result['compliant'] else None
                }

                for check_id, remediate_func in remediation_map.items():
                    if check_id not in skip_check_ids and check_id in scan_results:
                        result = remediate_func(scan_results[check_id])
                        if result is True:
                            print(f"CIS {check_id} remediated for cluster {cluster_name}")
                        elif isinstance(result, str):
                            print(f"CIS {check_id} remediated for cluster {cluster_name}: {result}")
                        elif result is False:
                            print(f"Failed to remediate CIS {check_id} for cluster {cluster_name}")
        
    except Exception as e:
        print(f"Error creating Kubernetes session: {e}")
        print(f"Full traceback: {traceback.format_exc()}")
    
def main():
    parser = argparse.ArgumentParser(description='AWS Configuration Tool')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    parser.add_argument("--auto", action="store_true", help="Run scheduled task without interaction")
    parser.add_argument("--interactive", action="store_true", help="Run AWS tool under interaction mode")
    parser.add_argument('--custom', action='store_true', help='Configure which checks to skip')
    
    args = parser.parse_args()
   
    if args.interactive:
        interactive_cli()

    elif args.auto:
        profiles = get_all_aws_profiles()
        if not profiles:
            print("No AWS profiles found in ~/.aws/credentials.")
            return

        for profile in profiles:
            print(f"Starting scan for profile: {profile}")
            session = create_aws_session(profile)
            if session:
                skip_checks = load_skip_config()
                enable_fix_ids = load_enable_fix_config()
                create_k8s_session(session, profile, skip_checks=skip_checks, enable_fix_ids=enable_fix_ids) 

if __name__ == '__main__':
    main()