import boto3
import subprocess
import tempfile
import os

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