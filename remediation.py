import time
import boto3
import subprocess
import tempfile
import os

def get_instance_id_by_node(ec2_client, node_name):
    try:
        resp = ec2_client.describe_instances(
            Filters=[{"Name": "private-dns-name", "Values": [node_name]}]
        )
        return resp["Reservations"][0]["Instances"][0]["InstanceId"]
    except Exception as e:
        print(f"[ERROR] Could not find instance ID for {node_name}: {e}")
        return None

def remediate_cis_2_1_1(client, cluster_name):
    print(f"Remediating CIS 2.1.1 for cluster {cluster_name}")
    try:
        # Enable all logging types
        client.update_cluster_config(
            name=cluster_name,
            logging={
                'clusterLogging': [
                    {
                        'types': [
                            'api',
                            'audit',
                            'authenticator',
                            'controllerManager',
                            'scheduler'
                        ],
                        'enabled': True
                    }
                ]
            }
        )
        return True
    except Exception as cluster_error:
        print(f"Failed to update cluster {cluster_name}: {str(cluster_error)}")
        return False
    
def remediate_cis_3_1_1(cluster_name, region, non_compliant_nodes):
    
    for node_name, file_paths in non_compliant_nodes.items():
        temp_file_path = None
        try:
            subprocess.run(
            f"aws eks update-kubeconfig --name {cluster_name} --region {region}",
            shell=True, check=True)
            
            pod_yaml = (
                "apiVersion: v1\n"
                "kind: Pod\n"
                "metadata:\n"
                "  name: file-check\n"
                "  namespace: default\n"
                "spec:\n"
                f"  nodeName: {node_name}\n"
                "  volumes:\n"
                "  - name: host-root\n"
                "    hostPath:\n"
                "      path: /\n"
                "      type: Directory\n"
                "  containers:\n"
                "  - name: nsenter\n"
                "    image: busybox\n"
                "    command: [\"sleep\", \"3600\"]\n"
                "    volumeMounts:\n"
                "    - name: host-root\n"
                "      mountPath: /host\n"
                "    securityContext:\n"
                "      privileged: true\n"
                "  tolerations:\n"
                "  - effect: NoSchedule\n"
                "    operator: Exists\n"
            )
            # Write YAML to temporary file
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as temp_file:
                temp_file.write(pod_yaml)
                temp_file_path = temp_file.name
            
            # Create Pod using the file
            create_pod_cmd = f"kubectl apply -f {temp_file_path}"
            subprocess.run(create_pod_cmd, shell=True, check=True)
            
            # 2. Wait for Pod to be ready
            subprocess.run("kubectl wait --for=condition=Ready pod/file-check --timeout=60s",
                         shell=True, check=True)
            
            for file_path in file_paths:
                chmod_cmd = f'kubectl exec -it file-check -- chmod 644 {file_path}'
                chmod_result = subprocess.run(chmod_cmd, shell=True, capture_output=True, text=True)

                if chmod_result.returncode != 0:
                    print(f"Failed to remediate {file_path}: {chmod_result.stderr}")
                    return False
                
        finally:

            delete_cmd = "kubectl delete pod file-check --ignore-not-found"
            subprocess.run(delete_cmd, shell=True, check=True)

            wait_cmd = "kubectl wait --for=delete pod/file-check --timeout=60s || true"
            subprocess.run(wait_cmd, shell=True)

            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)

    return True

def remediate_cis_3_1_2(cluster_name, region, non_compliant_nodes):

    for node_name, file_paths in non_compliant_nodes.items():
        temp_file_path = None
        try:
            subprocess.run(
            f"aws eks update-kubeconfig --name {cluster_name} --region {region}",
            shell=True, check=True)
            
            pod_yaml = (
                "apiVersion: v1\n"
                "kind: Pod\n"
                "metadata:\n"
                "  name: file-check\n"
                "  namespace: default\n"
                "spec:\n"
                f"  nodeName: {node_name}\n"
                "  volumes:\n"
                "  - name: host-root\n"
                "    hostPath:\n"
                "      path: /\n"
                "      type: Directory\n"
                "  containers:\n"
                "  - name: nsenter\n"
                "    image: busybox\n"
                "    command: [\"sleep\", \"3600\"]\n"
                "    volumeMounts:\n"
                "    - name: host-root\n"
                "      mountPath: /host\n"
                "    securityContext:\n"
                "      privileged: true\n"
                "  tolerations:\n"
                "  - effect: NoSchedule\n"
                "    operator: Exists\n"
            )
            # Write YAML to temporary file
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as temp_file:
                temp_file.write(pod_yaml)
                temp_file_path = temp_file.name
            
            # Create Pod using the file
            create_pod_cmd = f"kubectl apply -f {temp_file_path}"
            subprocess.run(create_pod_cmd, shell=True, check=True)
            
            # 2. Wait for Pod to be ready
            subprocess.run("kubectl wait --for=condition=Ready pod/file-check --timeout=60s",
                         shell=True, check=True)
            
            for file_path in file_paths:
                chmod_cmd = f'kubectl exec -it file-check -- chown root:root {file_path}'
                chmod_result = subprocess.run(chmod_cmd, shell=True, capture_output=True, text=True)

                if chmod_result.returncode != 0:
                    print(f"Failed to remediate {file_path}: {chmod_result.stderr}")
                    return False
                
        finally:

            delete_cmd = "kubectl delete pod file-check --ignore-not-found"
            subprocess.run(delete_cmd, shell=True, check=True)

            wait_cmd = "kubectl wait --for=delete pod/file-check --timeout=60s || true"
            subprocess.run(wait_cmd, shell=True)

            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)

    return True
        
def remediate_cis_3_1_3(cluster_name, region, non_compliant_nodes):
    
    for node_name, file_paths in non_compliant_nodes.items():
        temp_file_path = None
        try:
            subprocess.run(
            f"aws eks update-kubeconfig --name {cluster_name} --region {region}",
            shell=True, check=True)
            
            pod_yaml = (
                "apiVersion: v1\n"
                "kind: Pod\n"
                "metadata:\n"
                "  name: file-check\n"
                "  namespace: default\n"
                "spec:\n"
                f"  nodeName: {node_name}\n"
                "  volumes:\n"
                "  - name: host-root\n"
                "    hostPath:\n"
                "      path: /\n"
                "      type: Directory\n"
                "  containers:\n"
                "  - name: nsenter\n"
                "    image: busybox\n"
                "    command: [\"sleep\", \"3600\"]\n"
                "    volumeMounts:\n"
                "    - name: host-root\n"
                "      mountPath: /host\n"
                "    securityContext:\n"
                "      privileged: true\n"
                "  tolerations:\n"
                "  - effect: NoSchedule\n"
                "    operator: Exists\n"
            )
            # Write YAML to temporary file
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as temp_file:
                temp_file.write(pod_yaml)
                temp_file_path = temp_file.name
            
            # Create Pod using the file
            create_pod_cmd = f"kubectl apply -f {temp_file_path}"
            subprocess.run(create_pod_cmd, shell=True, check=True)
            
            # 2. Wait for Pod to be ready
            subprocess.run("kubectl wait --for=condition=Ready pod/file-check --timeout=60s",
                         shell=True, check=True)
            
            for file_path in file_paths:
                chmod_cmd = f'kubectl exec -it file-check -- chmod 644 {file_path}'
                chmod_result = subprocess.run(chmod_cmd, shell=True, capture_output=True, text=True)

                if chmod_result.returncode != 0:
                    print(f"Failed to remediate {file_path}: {chmod_result.stderr}")
                    return False
                
        finally:

            delete_cmd = "kubectl delete pod file-check --ignore-not-found"
            subprocess.run(delete_cmd, shell=True, check=True)

            wait_cmd = "kubectl wait --for=delete pod/file-check --timeout=60s || true"
            subprocess.run(wait_cmd, shell=True)

            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)

    return True

def remediate_cis_3_1_4(cluster_name, region, non_compliant_nodes):

    for node_name, file_paths in non_compliant_nodes.items():
        temp_file_path = None
        try:
            subprocess.run(
            f"aws eks update-kubeconfig --name {cluster_name} --region {region}",
            shell=True, check=True)
            
            pod_yaml = (
                "apiVersion: v1\n"
                "kind: Pod\n"
                "metadata:\n"
                "  name: file-check\n"
                "  namespace: default\n"
                "spec:\n"
                f"  nodeName: {node_name}\n"
                "  volumes:\n"
                "  - name: host-root\n"
                "    hostPath:\n"
                "      path: /\n"
                "      type: Directory\n"
                "  containers:\n"
                "  - name: nsenter\n"
                "    image: busybox\n"
                "    command: [\"sleep\", \"3600\"]\n"
                "    volumeMounts:\n"
                "    - name: host-root\n"
                "      mountPath: /host\n"
                "    securityContext:\n"
                "      privileged: true\n"
                "  tolerations:\n"
                "  - effect: NoSchedule\n"
                "    operator: Exists\n"
            )
            # Write YAML to temporary file
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as temp_file:
                temp_file.write(pod_yaml)
                temp_file_path = temp_file.name
            
            # Create Pod using the file
            create_pod_cmd = f"kubectl apply -f {temp_file_path}"
            subprocess.run(create_pod_cmd, shell=True, check=True)
            
            # 2. Wait for Pod to be ready
            subprocess.run("kubectl wait --for=condition=Ready pod/file-check --timeout=60s",
                         shell=True, check=True)
            
            for file_path in file_paths:
                chmod_cmd = f'kubectl exec -it file-check -- chown root:root {file_path}'
                chmod_result = subprocess.run(chmod_cmd, shell=True, capture_output=True, text=True)

                if chmod_result.returncode != 0:
                    print(f"Failed to remediate {file_path}: {chmod_result.stderr}")
                    return False
                
        finally:

            delete_cmd = "kubectl delete pod file-check --ignore-not-found"
            subprocess.run(delete_cmd, shell=True, check=True)

            wait_cmd = "kubectl wait --for=delete pod/file-check --timeout=60s || true"
            subprocess.run(wait_cmd, shell=True)

            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)

    return True

def remediate_3_2_1(region, non_compliant_nodes):

    ec2 = boto3.client("ec2", region_name=region)
    ssm = boto3.client("ssm", region_name=region)

    for node_name in non_compliant_nodes.keys():

        # Step 1: Get instance ID
        instance_id = get_instance_id_by_node(ec2, node_name)
        if not instance_id:
            print(f"[SKIP] Could not resolve EC2 instance ID for {node_name}")
            continue

        # Step 2: Check if managed by SSM
        try:
            info = ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
            )
            if not info["InstanceInformationList"]:
                print(f"[SKIP] Instance {instance_id} is not managed by SSM")
                continue
        except Exception as e:
            print(f"[ERROR] SSM status check failed for {instance_id}: {e}")
            continue

        # Step 3: Execute remediation command (disable anonymous auth and restart kubelet)
        patch_and_restart_cmd = """
CONFIG=/etc/kubernetes/kubelet/kubelet-config.json
if [ -f "$CONFIG" ]; then
  jq '.authentication.anonymous.enabled = false' "$CONFIG" > /tmp/tmp-kubelet-config.json && \
  mv /tmp/tmp-kubelet-config.json "$CONFIG" && \
  systemctl restart kubelet
else
  echo "Config not found" && exit 1
fi
"""
        try:
            res = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={'commands': [patch_and_restart_cmd]},
            )
            command_id = res["Command"]["CommandId"]
            time.sleep(2)

            result = ssm.get_command_invocation(
                CommandId=command_id, InstanceId=instance_id
            )

            if result["Status"] != "Success":
                print(f"[ERROR] Remediation failed on {node_name}: {result['StandardErrorContent']}")
                
        except Exception as e:
            print(f"[ERROR] SSM command failed for {node_name}: {e}")
    
    return True
