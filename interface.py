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

        else:
            print(f"Unknown command: {command}")

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

def interactive_cli():
    '''Trigger the interactive CLI'''

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
            print("  help - Display this help information")
            print("  exit - Exit the program")

        elif command.lower() == 'configure':
            profile = input("Profile name (leave empty for default): ").strip()
            configure_aws_profile(profile if profile else None)
        
        elif command.lower() == 'k8s':
            profile = input("Profile name (leave empty for default): ").strip()
            session = create_aws_session(profile if profile else None)
            create_k8s_session(session)
            
def create_k8s_session(session):
    '''Create a Kubernetes session'''
    try:
        eks_client = session.client("eks")
        region = eks_client._client_config.region_name
        print(f"Region: {region}")
        cluster_names = []
         #list all clusters in the account
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

                """
                result_1 = scan.cis_2_1_1(cluster_data)
                result_2 = scan.cis_2_1_2(kconfig, cluster_name, region)
                result_3 = scan.cis_3_1_1(kconfig, cluster_name, region)
                result_4 = scan.cis_3_1_2(kconfig, cluster_name, region)
                result_5 = scan.cis_3_1_3(kconfig, cluster_name, region)
                result_6 = scan.cis_3_1_4(kconfig, cluster_name, region)
                result_7 = scan.cis_3_2_1(kconfig, cluster_name, region)

                results = [result_1, result_2, result_3, result_4, result_5, result_6, result_7]
                report_filename = f"compliance_report_{cluster_name}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pdf"
                report_generator.generate_pdf_report(results, report_filename, cluster_name, include_compliant=True)

                if result_1['compliant'] == False:
                    remediation.remediate_cis_2_1_1(eks_client, cluster_name)
                
                #if result_3['compliant'] == False:
                    #remediation.remediate_cis_3_1_1(cluster_name, region, result_3['details'])
                """
                
                
       
    except Exception as e:
        print(f"Error creating Kubernetes session: {e}")
    
def main():
    parser = argparse.ArgumentParser(description='AWS Configuration Tool')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    parser.add_argument('--profile', help='Name of the AWS profile to configure')
    parser.add_argument("--auto", action="store_true", help="Run scheduled task without interaction")
    parser.add_argument("--interactive", action="store_true", help="Run AWS tool under interaction mode")

    
    args = parser.parse_args()
   
    if args.interactive:
        interactive_cli()

if __name__ == '__main__':
    main()