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

        elif command.lower() == 'configure':
            profile = input("Profile name (leave empty for default): ").strip()
            configure_aws_profile(profile if profile else None)

        elif command.lower() == 'k8s':
            profile = input("Profile name (leave empty for default): ").strip()
            session = create_aws_session(profile if profile else None)
            create_k8s_session(session) 
        
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

def get_cis_checks():
   
    return [
        {"id": "2.1.1", "number": 1, "name": "Ensure Amazon EKS control plane logging is enabled"},
        {"id": "2.1.2", "number": 2, "name": "Ensure Amazon EKS cluster endpoint access is restricted"},
        {"id": "3.1.1", "number": 3, "name": "Ensure security groups for EKS clusters restrict access"},
        {"id": "3.1.2", "number": 4, "name": "Ensure that EKS security groups restrict access to API server"},
        {"id": "3.1.3", "number": 5, "name": "Ensure EKS clusters are created with Private Endpoint"},
        {"id": "3.1.4", "number": 6, "name": "Ensure EKS clusters are configured with security groups"},
        {"id": "3.2.1", "number": 7, "name": "Ensure EKS Clusters are created with KMS encryption"},
        {"id": "3.2.2", "number": 8, "name": "Ensure EKS Clusters have Secrets Encryption Enabled"},
        {"id": "3.2.3", "number": 9, "name": "Ensure EKS Clusters audit logs are enabled"},
        {"id": "3.2.4", "number": 10, "name": "Ensure EKS Clusters are using latest platform version"},
        {"id": "3.2.5", "number": 11, "name": "Ensure EKS Clusters are using latest Kubernetes version"},
        {"id": "3.2.6", "number": 12, "name": "Ensure EKS Clusters have endpoint public access disabled"},
        {"id": "3.2.7", "number": 13, "name": "Ensure EKS Cluster endpoint private access is enabled"},
        {"id": "3.2.8", "number": 14, "name": "Ensure EKS Cluster Subnets are specific"},
        {"id": "3.2.9", "number": 15, "name": "Ensure EKS has adequate logging and monitoring"},
        {"id": "4.1.1", "number": 16, "name": "Ensure that RBAC is enabled and used"},
        {"id": "4.1.2", "number": 17, "name": "Ensure RBAC permissions are limited to necessary roles"},
        {"id": "4.1.3", "number": 18, "name": "Ensure pods have limited access to host"},
        {"id": "4.1.4", "number": 19, "name": "Ensure impersonation permissions are restricted"},
        {"id": "4.1.5", "number": 20, "name": "Ensure default service account has no roles or cluster roles bound"},
        {"id": "4.1.6", "number": 21, "name": "Ensure service accounts tokens are only used where necessary"},
        {"id": "4.1.7", "number": 22, "name": "Ensure pod security policies are used"},
        {"id": "4.1.8", "number": 23, "name": "Ensure role-based access control is used"},
        {"id": "4.2.1", "number": 24, "name": "Ensure container host security"},
        {"id": "4.2.2", "number": 25, "name": "Ensure container filesystem security"},
        {"id": "4.2.3", "number": 26, "name": "Ensure container network security"},
        {"id": "4.2.4", "number": 27, "name": "Ensure container runtime security"},
        {"id": "4.2.5", "number": 28, "name": "Ensure container process security"},
        {"id": "4.3.1", "number": 29, "name": "Ensure EKS nodes are using optimal OS AMI"},
        {"id": "4.3.2", "number": 30, "name": "Ensure nodes have adequate security measures"},
        {"id": "4.4.1", "number": 31, "name": "Ensure cluster networking configuration is secure"},
        {"id": "4.4.2", "number": 32, "name": "Ensure network policy is configured properly"},
        {"id": "4.5.1", "number": 33, "name": "Ensure EKS clusters are properly secured"},
        {"id": "4.5.2", "number": 34, "name": "Ensure EKS clusters have critical security patches applied"}
    ]

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
    """
    Call aws configure command to set up AWS credentials for the specified profile
    If profile_name is not specified, configure the default profile
    """
    cmd = ['aws', 'configure']
    
    if profile_name:
        cmd.extend(['--profile', profile_name])
    
    print(f"\nStarting AWS configuration for {'profile ' + profile_name if profile_name else 'default profile'}")
    print("Please enter your AWS credentials and settings as prompted\n")
    
    try:
        # Run aws configure command
        subprocess.run(cmd, shell=True, check=True)
        
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
    """
    Use boto3 to create a session with the specified AWS profile
    """
    try:
        session = boto3.Session(profile_name=profile_name)
        return session
    except Exception as e:
        print(f"Error creating session with '{profile_name}' Specific error is: {e}")
        return None
            
def create_k8s_session(session, skip_checks=None):
    '''Create a Kubernetes session'''
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
                result = subprocess.run(f"aws eks get-token --cluster-name {cluster_name}", shell=True, capture_output=True, text=True)
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
                
                """
                result_1 = scan.cis_2_1_1(cluster_data)
                result_2 = scan.cis_2_1_2(kconfig, cluster_name, region)
                result_3 = scan.cis_3_1_1(kconfig, cluster_name, region)
                result_4 = scan.cis_3_1_2(kconfig, cluster_name, region)
                result_5 = scan.cis_3_1_3(kconfig, cluster_name, region)
                result_6 = scan.cis_3_1_4(kconfig, cluster_name, region)
                result_7 = scan.cis_3_2_1(kconfig, cluster_name, region)
                result_8 = scan.cis_3_2_2(kconfig, cluster_name, region)
                result_9 = scan.cis_3_2_3(kconfig, cluster_name, region)
                result_10 = scan.cis_3_2_4(kconfig, cluster_name, region)
                result_11 = scan.cis_3_2_5(kconfig, cluster_name, region)
                result_12 = scan.cis_3_2_6(kconfig, cluster_name, region)
                result_13 = scan.cis_3_2_7(kconfig, cluster_name, region)
                result_14 = scan.cis_3_2_8(kconfig, cluster_name, region)
                result_15 = scan.cis_3_2_9(kconfig, cluster_name, region)
                result_16 = scan.cis_4_1_1(kconfig, cluster_name)
                result_17 = scan.cis_4_1_2(kconfig, cluster_name)
                result_18 = scan.cis_4_1_3(kconfig, cluster_name)
                result_19 = scan.cis_4_1_4(kconfig, cluster_name)
                result_20 = scan.cis_4_1_5(kconfig, cluster_name)
                result_21 = scan.cis_4_1_6(kconfig, cluster_name)   
                result_22 = scan.cis_4_1_7(cluster_name, region)
                result_23 = scan.cis_4_1_8(kconfig, cluster_name)
                result_24 = scan.cis_4_2_1(kconfig, cluster_name)
                result_25 = scan.cis_4_2_2(kconfig, cluster_name)
                result_26 = scan.cis_4_2_3(kconfig, cluster_name)
                result_27 = scan.cis_4_2_4(kconfig, cluster_name)
                result_28 = scan.cis_4_2_5(kconfig, cluster_name)
                result_29 = scan.cis_4_3_1(cluster_name, region)
                result_30 = scan.cis_4_3_2(cluster_name, region)
                result_31 = scan.cis_4_4_1(cluster_name, region)
                result_32 = scan.cis_4_4_2(cluster_name)
                result_33 = scan.cis_4_5_1(cluster_name, region)
                result_34 = scan.cis_4_5_2(cluster_name, region)
                """
                scan_map = {
                "2.1.1": lambda: scan.cis_2_1_1(cluster_data),
                "2.1.2": lambda: scan.cis_2_1_2(kconfig, cluster_name, region),
                "3.1.1": lambda: scan.cis_3_1_1(kconfig, cluster_name, region),
                "3.1.2": lambda: scan.cis_3_1_2(kconfig, cluster_name, region),
                "3.1.3": lambda: scan.cis_3_1_3(kconfig, cluster_name, region),
                "3.1.4": lambda: scan.cis_3_1_4(kconfig, cluster_name, region),
                "3.2.1": lambda: scan.cis_3_2_1(kconfig, cluster_name, region),
                "3.2.2": lambda: scan.cis_3_2_2(kconfig, cluster_name, region),
                "3.2.3": lambda: scan.cis_3_2_3(kconfig, cluster_name, region),
                "3.2.4": lambda: scan.cis_3_2_4(kconfig, cluster_name, region),
                "3.2.5": lambda: scan.cis_3_2_5(kconfig, cluster_name, region),
                "3.2.6": lambda: scan.cis_3_2_6(kconfig, cluster_name, region),
                "3.2.7": lambda: scan.cis_3_2_7(kconfig, cluster_name, region),
                "3.2.8": lambda: scan.cis_3_2_8(kconfig, cluster_name, region),
                "3.2.9": lambda: scan.cis_3_2_9(kconfig, cluster_name, region),
                "4.1.1": lambda: scan.cis_4_1_1(kconfig, cluster_name),
                "4.1.2": lambda: scan.cis_4_1_2(kconfig, cluster_name),
                "4.1.3": lambda: scan.cis_4_1_3(kconfig, cluster_name),
                "4.1.4": lambda: scan.cis_4_1_4(kconfig, cluster_name),
                "4.1.5": lambda: scan.cis_4_1_5(kconfig, cluster_name),
                "4.1.6": lambda: scan.cis_4_1_6(kconfig, cluster_name),
                "4.1.7": lambda: scan.cis_4_1_7(cluster_name, region),
                "4.1.8": lambda: scan.cis_4_1_8(kconfig, cluster_name),
                "4.2.1": lambda: scan.cis_4_2_1(kconfig, cluster_name),
                "4.2.2": lambda: scan.cis_4_2_2(kconfig, cluster_name),
                "4.2.3": lambda: scan.cis_4_2_3(kconfig, cluster_name),
                "4.2.4": lambda: scan.cis_4_2_4(kconfig, cluster_name),
                "4.2.5": lambda: scan.cis_4_2_5(kconfig, cluster_name),
                "4.3.1": lambda: scan.cis_4_3_1(cluster_name, region),
                "4.3.2": lambda: scan.cis_4_3_2(cluster_name, region),
                "4.4.1": lambda: scan.cis_4_4_1(cluster_name, region),
                "4.4.2": lambda: scan.cis_4_4_2(cluster_name),
                "4.5.1": lambda: scan.cis_4_5_1(cluster_name, region),
                "4.5.2": lambda: scan.cis_4_5_2(cluster_name, region)
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
                "2.1.1": lambda result: remediation.remediate_cis_2_1_1(cluster_name, region) if not result['compliant'] else None,
                "3.1.1": lambda result: remediation.remediate_cis_3_1_1(cluster_name, region, result['details']) if not result['compliant'] else None,
                "3.1.2": lambda result: remediation.remediate_cis_3_1_2(cluster_name, region, result['details']) if not result['compliant'] else None,
                "3.1.3": lambda result: remediation.remediate_cis_3_1_3(cluster_name, region, result['details']) if not result['compliant'] else None,
                "3.1.4": lambda result: remediation.remediate_cis_3_1_4(cluster_name, region, result['details']) if not result['compliant'] else None,
                "3.2.1": lambda result: remediation.remediate_cis_3_2_1(region, result['details']) if not result['compliant'] else None,
                "3.2.2": lambda result: remediation.remediate_cis_3_2_2(region, result['details']) if not result['compliant'] else None,
                "3.2.3": lambda result: remediation.remediate_cis_3_2_3(region, result['details']) if not result['compliant'] else None,
                "3.2.4": lambda result: remediation.remediate_cis_3_2_4(region, result['details']) if not result['compliant'] else None,
                "3.2.5": lambda result: remediation.remediate_cis_3_2_5(region, result['details']) if not result['compliant'] else None,
                "3.2.6": lambda result: remediation.remediate_cis_3_2_6(region, result['details']) if not result['compliant'] else None,
                "3.2.7": lambda result: remediation.remediate_cis_3_2_7(region, result['details']) if not result['compliant'] else None,
                "3.2.8": lambda result: remediation.remediate_cis_3_2_8(region, result['details']) if not result['compliant'] else None,
                "3.2.9": lambda result: remediation.remediate_cis_3_2_9(region, result['details']) if not result['compliant'] else None,
                "4.1.1": lambda result: remediation.remediate_cis_4_1_1(result['details'], enable_fix=False) if not result['compliant'] else None,
                "4.1.5": lambda result: remediation.remediate_cis_4_1_5(enable_fix=False) if not result['compliant'] else None,
                "4.2.1": lambda result: remediation.remediate_cis_4_2_x(cluster_name, result['details'], enable_fix=False) if not result['compliant'] else None,
                "4.3.2": lambda result: remediation.remediate_cis_4_3_2(cluster_name, region, result['details'], enable_fix=False) if not result['compliant'] else None,
                "4.4.1": lambda result: remediation.remediate_cis_4_4_1(cluster_name) if not result['compliant'] else None,
                "4.5.1": lambda result: remediation.remediate_cis_4_5_1(cluster_name) if not result['compliant'] else None,
                "4.5.2": lambda result: remediation.remediate_cis_4_5_2(cluster_name, region, result['details'], enable_fix=False) if not result['compliant'] else None
                }

                for check_id, remediate_func in remediation_map.items():
                    if check_id not in skip_check_ids and check_id in scan_results:
                        result = remediate_func(scan_results[check_id])
                        if result:
                            print(f"CIS {check_id} remediated for cluster {cluster_name}")
                        elif result is not None:  
                            print(f"Failed to remediate CIS {check_id} for cluster {cluster_name}")

                """

                if result_1['compliant'] == False:
                    result=remediation.remediate_cis_2_1_1(cluster_name, region)
                    if result:
                        print(f"CIS 2.1.1 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 2.1.1 for cluster {cluster_name}")
                
                if result_3['compliant'] == False:
                    result = remediation.remediate_cis_3_1_1(cluster_name, region, result_3['details'])
                    if result:
                        print(f"CIS 3.1.1 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 3.1.1 for cluster {cluster_name}")

                if result_4['compliant'] == False:
                    result = remediation.remediate_cis_3_1_2(cluster_name, region, result_4['details'])
                    if result:
                        print(f"CIS 3.1.2 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 3.1.2 for cluster {cluster_name}")

                if result_5['compliant'] == False:
                    result = remediation.remediate_cis_3_1_3(cluster_name, region, result_5['details'])
                    if result:
                        print(f"CIS 3.1.3 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 3.1.3 for cluster {cluster_name}")

                if result_6['compliant'] == False:
                    result = remediation.remediate_cis_3_1_4(cluster_name, region, result_6['details'])
                    if result:
                        print(f"CIS 3.1.4 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 3.1.4 for cluster {cluster_name}")

                if result_7['compliant'] == False:
                    result = remediation.remediate_cis_3_2_1(region, result_7['details'])
                    if result:
                        print(f"CIS 3.2.1 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 3.2.1 for cluster {cluster_name}")

                if result_8['compliant'] == False:
                    result = remediation.remediate_cis_3_2_2(region, result_8['details'])
                    if result:
                        print(f"CIS 3.2.2 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 3.2.2 for cluster {cluster_name}")

                if result_9['compliant'] == False:
                    result = remediation.remediate_cis_3_2_3(region, result_9['details'])
                    if result:
                        print(f"CIS 3.2.3 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 3.2.3 for cluster {cluster_name}")

                if result_10['compliant'] == False:
                    result = remediation.remediate_cis_3_2_4(region, result_10['details'])
                    if result:
                        print(f"CIS 3.2.4 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 3.2.4 for cluster {cluster_name}")

                if result_11['compliant'] == False:
                    result = remediation.remediate_cis_3_2_5(region, result_11['details'])
                    if result:
                        print(f"CIS 3.2.5 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 3.2.5 for cluster {cluster_name}")

                if result_12['compliant'] == False:
                    result = remediation.remediate_cis_3_2_6(region, result_12['details'])
                    if result:
                        print(f"CIS 3.2.6 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 3.2.6 for cluster {cluster_name}")

                if result_13['compliant'] == False:
                    result = remediation.remediate_cis_3_2_7(region, result_13['details'])
                    if result:
                        print(f"CIS 3.2.7 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 3.2.7 for cluster {cluster_name}")

                if result_14['compliant'] == False:
                    result = remediation.remediate_cis_3_2_8(region, result_14['details'])
                    if result:
                        print(f"CIS 3.2.8 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 3.2.8 for cluster {cluster_name}")

                if result_15['compliant'] == False:
                    result = remediation.remediate_cis_3_2_9(region, result_15['details'])
                    if result:
                        print(f"CIS 3.2.9 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 3.2.9 for cluster {cluster_name}")

                if result_16['compliant'] == False:
                    result = remediation.remediate_cis_4_1_1(result_16['details'], enable_fix=False)
                    if result:
                        print(f"CIS 4.1.1 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 4.1.1 for cluster {cluster_name}")

                if result_20['compliant'] == False:
                    result = remediation.remediate_cis_4_1_5(enable_fix=False)
                    if result:
                        print(f"CIS 4.1.5 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 4.1.5 for cluster {cluster_name}")

                if result_24['compliant'] == False:
                    result = remediation.remediate_cis_4_2_x(cluster_name, result_24['details'], enable_fix=False)
                    if result:
                        print(f"CIS 4.2.1 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 4.2.1 for cluster {cluster_name}")

                if result_30['compliant'] == False:
                    result = remediation.remediate_cis_4_3_2(cluster_name, region, result_30['details'], enable_fix=False)
                    if result:
                        print(f"CIS 4.3.2 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 4.3.2 for cluster {cluster_name}")

                if result_31['compliant'] == False:
                    result = remediation.remediate_cis_4_4_1(cluster_name)
                    if result:
                        print(f"CIS 4.4.1 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 4.4.1 for cluster {cluster_name}")  

                if result_33['compliant'] == False:
                    result = remediation.remediate_cis_4_5_1(cluster_name)
                    if result:
                        print(f"CIS 4.5.1 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 4.5.1 for cluster {cluster_name}")

                if result_34['compliant'] == False:
                    result = remediation.remediate_cis_4_5_2(cluster_name, region, result_34['details'], enable_fix=False)
                    if result:
                        print(f"CIS 4.5.2 remediated for cluster {cluster_name}")
                    else:
                        print(f"Failed to remediate CIS 4.5.2 for cluster {cluster_name}")
                """
        
    except Exception as e:
        print(f"Error creating Kubernetes session: {e}")
    
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
                create_k8s_session(session, skip_checks=skip_checks)

    elif args.custom:
        skip_checks = select_checks_to_skip()
        save_skip_config(skip_checks)
        print("Configuration complete.")
        return
if __name__ == '__main__':
    main()