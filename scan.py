import kubernetes
import subprocess
import tempfile
import json
import time
import requests
import os
import boto3


# CIS 2.1.1. Check if audit logs are enabled for an Amazon EKS cluster.
def cis_2_1_1(cluster_data):

    required_log_types = {
        'api': False,          
        'audit': False,          
        'authenticator': False, 
        'controllerManager': False, 
        'scheduler': False       
    }
    
    result = {
        'check_id': "2.1.1",
        'title': "Enable audit Logs",
        'resource_id': cluster_data.get('name', 'unknown-cluster'),
        'compliant': False,
        'details': required_log_types.copy()
    }
    
    # Check if logging configuration exists.
    if 'logging' not in cluster_data:
        return result

    cluster_logging = cluster_data['logging'].get('clusterLogging', [])
    for logging_config in cluster_logging:
        if logging_config.get('enabled', False):
            enabled_types = logging_config.get('types', [])
            for log_type in enabled_types:
                if log_type in required_log_types:
                    result['details'][log_type] = True

    result['compliant'] = all(result['details'].values())

    print("CIS 2.1.1 Scan Completed")
    return result

# CIS 2.1.2 Ensure audit logs are collected and managed
def cis_2_1_2(kube_config, cluster_name, region):

    result = {
        'check_id': "2.1.2",
        'title': "Ensure audit logs are collected and managed",
        'resource_id': cluster_name,
        'compliant': False,
        'details': []
    }

    non_compliant_nodes = []
    # Update kubeconfig for the kubeclt
    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region}",
        shell=True, check=True
    )

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)

    nodes = api.list_node()
    for node in nodes.items:
        has_audit_policy = False
        node_name = node.metadata.name
        command = f"kubectl get --raw /api/v1/nodes/{node_name}/proxy/configz"
        policy_result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if policy_result.returncode == 0:
            try:
                config_data = json.loads(policy_result.stdout)  
                audit_policy = config_data.get("kubeletConfig", {}).get("auditPolicy", None)
                if audit_policy is None:
                    non_compliant_nodes.append(node_name)
                else:
                    has_audit_policy = True
            except json.JSONDecodeError:
                print("Failed to parse JSON response")
        else:
            print(f"Failed to execute command: {policy_result.stderr.strip()}")
        

        if has_audit_policy:
            audit_log_command = f"kubectl get --raw /api/v1/nodes/{node_name}/proxy/stats/summary"
            audit_log_result = subprocess.run(audit_log_command, shell=True, capture_output=True, text=True)
        
            if audit_log_result.returncode == 0:
                try:
                    stats_data = json.loads(audit_log_result.stdout)
                    audit_logs = stats_data.get("auditLogs", None)
                    
                    if audit_logs is None:
                        non_compliant_nodes.append(node_name)
                except json.JSONDecodeError:
                    print("Failed to parse JSON response")
    
    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True
    
    print("CIS 2.1.2 Scan Completed")
    return result

# CIS 3.1.1 Ensure that the kubeconfig file permissions are set to 644 or more restrictive.
def cis_3_1_1(kube_config, cluster_name, region):
    
    result = {
        'check_id': "3.1.1",
        'title': "Ensure that the kubeconfig file permissions are set to 644 or more restrictive.",
        'resource_id': cluster_name,
        'compliant': False,
        'details': {}
    }
     
    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)
    
    nodes = api.list_node()
    non_compliant_files = {} 
    for node in nodes.items:
        node_name = node.metadata.name
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
        
            
            # 3. Execute command to check file permissions
            find_cmd = 'kubectl exec -it file-check -- sh -c "find /host -name kubeconfig 2>/dev/null -exec ls -l {} \\;"'
            find_result = subprocess.run(find_cmd, shell=True, capture_output=True, text=True)
            
            # Check if all kubeconfig files comply with requirements
            found_kubeconfig = False
            node_non_compliant_files = []
            lines = find_result.stdout.strip().split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Only check file lines where the filename is exactly kubeconfig
                if line.startswith('-') and "kubeconfig" in line:
                    found_kubeconfig = True
                    parts = line.split()
                    if len(parts) >= 9:
                        permission_str = parts[0]
                        full_path = parts[8]
                        # Check if permissions are 644 or more restrictive
                        if 'w' in permission_str[5:]:  # If group or others have write permission
                            node_non_compliant_files.append(full_path)
            
            if not found_kubeconfig:
                print(f"Node {node_name} has no kubeconfig file")
            
            elif not node_non_compliant_files:
                non_compliant_files[node_name] = node_non_compliant_files
        
        except Exception as e:
            print(f"Error checking node {node_name}: {str(e)}")
            continue
        finally:
            # 4. Clean up temporary files, remove Pod
            
            delete_cmd = "kubectl delete pod file-check --ignore-not-found"
            subprocess.run(delete_cmd, shell=True, check=True)

            wait_cmd = "kubectl wait --for=delete pod/file-check --timeout=60s || true"
            subprocess.run(wait_cmd, shell=True)

            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
        
    if non_compliant_files:
        result['compliant'] = False
        result['details'] = non_compliant_files
    else:
        result['compliant'] = True
    
    print("CIS 3.1.1 Scan Completed")
    return result

# 3.1.2 Ensure that the kubelet kubeconfig file ownership is set to root:root
def cis_3_1_2(kube_config, cluster_name, region):

    result = {
        'check_id': "3.1.2",
        'title': "Ensure that the kubelet kubeconfig file ownership is set to root:root",
        'resource_id': cluster_name,
        'compliant': False,
        'details': {}
    }

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)
    
    nodes = api.list_node()
    non_compliant_files = {} 
    for node in nodes.items:
        node_name = node.metadata.name
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
            wait_cmd = subprocess.run("kubectl wait --for=condition=Ready pod/file-check --timeout=60s",
                         shell=True, check=True)
            
            if wait_cmd.returncode != 0:
                print(f"[WARNING] Node {node_name}: Pod not ready. Reason:\n{wait_cmd.stderr.strip()}")
                continue 
            
            # 3. Execute command to check file permissions
            find_cmd = 'kubectl exec -it file-check -- sh -c "find /host -name kubeconfig 2>/dev/null -exec ls -l {} \\;"'
            find_result = subprocess.run(find_cmd, shell=True, capture_output=True, text=True)
            
            # Check if all kubeconfig files comply with requirements
            found_kubeconfig = False
            node_non_compliant_files = []
            lines = find_result.stdout.strip().split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Only check file lines where the filename is exactly kubeconfig
                if line.startswith('-') and "kubeconfig" in line:
                    found_kubeconfig = True
                    parts = line.split()
                    if len(parts) >= 9:
                        owner = parts[2]
                        group = parts[3]
                        full_path = parts[8]
                        
                        # Check if owner and group are root
                        if owner != "root" or group != "root": 
                            node_non_compliant_files.append(full_path)
            
            if not found_kubeconfig:
                print(f"Node {node_name} has no kubeconfig file")
            
            elif not node_non_compliant_files:
                non_compliant_files[node_name] = node_non_compliant_files
        
        except Exception as e:
            print(f"Error checking node {node_name}: {str(e)}")
            continue
        finally:
            # 4. Clean up temporary files, remove Pod
            
            delete_cmd = "kubectl delete pod file-check --ignore-not-found"
            subprocess.run(delete_cmd, shell=True, check=True)

            wait_cmd = "kubectl wait --for=delete pod/file-check --timeout=60s || true"
            subprocess.run(wait_cmd, shell=True)

            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
        
    if non_compliant_files:
            result['compliant'] = False
            result['details'] = non_compliant_files
    else:
            result['compliant'] = True
    
    print("CIS 3.1.2 Scan Completed")
    return result

# 3.1.3 Ensure that the kubelet kubeconfig file permissions are set to 644 or more restrictive
def cis_3_1_3(kube_config, cluster_name, region):

    result = {
        'check_id': "3.1.3",
        'title': "Ensure that the kubelet kubeconfig file permissions are set to 644 or more restrictive",
        'resource_id': cluster_name,
        'compliant': False,
        'details': {}
    }

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)
    
    nodes = api.list_node()
    non_compliant_files = {} 
    for node in nodes.items:
        node_name = node.metadata.name
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
            wait_cmd = subprocess.run("kubectl wait --for=condition=Ready pod/file-check --timeout=60s",
                         shell=True, check=True)
            
            if wait_cmd.returncode != 0:
                print(f"[WARNING] Node {node_name}: Pod not ready. Reason:\n{wait_cmd.stderr.strip()}")
                continue 
            
            # 3. Execute command to check file permissions
            find_cmd = "kubectl exec -it file-check -- ls -l /host/etc/kubernetes/kubelet/config"
            find_result = subprocess.run(find_cmd, shell=True, capture_output=True, text=True)
            
            # Check if all kubeconfig files comply with requirements
            found_config = False
            node_non_compliant_files = []
            lines = find_result.stdout.strip().split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Only check file lines where the filename is exactly config
                if line.startswith('-') and "/host/etc/kubernetes/kubelet/config" in line:
                    found_config = True
                    parts = line.split()
                    if len(parts) >= 9:
                        permission_str = parts[0]
                        full_path = parts[8]

                        # Check if permissions are 644 or more restrictive
                        if 'w' in permission_str[5:]:  # If group or others have write permission
                            node_non_compliant_files.append(full_path)
            
            if not found_config:
                print(f"Node {node_name} has no config file")
            
            elif not node_non_compliant_files:
                non_compliant_files[node_name] = node_non_compliant_files
        
        except Exception as e:
            print(f"Error checking node {node_name}: {str(e)}")
            continue
        finally:
            # 4. Clean up temporary files, remove Pod
            
            delete_cmd = "kubectl delete pod file-check --ignore-not-found"
            subprocess.run(delete_cmd, shell=True, check=True)

            wait_cmd = "kubectl wait --for=delete pod/file-check --timeout=60s || true"
            subprocess.run(wait_cmd, shell=True)

            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
        
    if non_compliant_files:
            result['compliant'] = False
            result['details'] = non_compliant_files
    else:
            result['compliant'] = True
    
    print("CIS 3.1.3 Scan Completed")
    return result

# 3.1.4 Ensure that the kubelet config file permissions are set to 644 or more restrictive
def cis_3_1_4(kube_config, cluster_name, region):

    result = {
        'check_id': "3.1.4",
        'title': "Ensure that the kubelet config file permissions are set to 644 or more restrictive",
        'resource_id': cluster_name,
        'compliant': False,
        'details': {}
    }

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)
    
    nodes = api.list_node()
    non_compliant_files = {} 
    for node in nodes.items:
        node_name = node.metadata.name
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
            wait_cmd = subprocess.run("kubectl wait --for=condition=Ready pod/file-check --timeout=60s",
                         shell=True, check=True)
            
            if wait_cmd.returncode != 0:
                print(f"[WARNING] Node {node_name}: Pod not ready. Reason:\n{wait_cmd.stderr.strip()}")
                continue 
            
            # 3. Execute command to check file permissions
            find_cmd = "kubectl exec -it file-check -- ls -l /host/etc/kubernetes/kubelet/config"
            find_result = subprocess.run(find_cmd, shell=True, capture_output=True, text=True)
            
            # Check if all kubeconfig files comply with requirements
            found_kubeconfig = False
            node_non_compliant_files = []
            lines = find_result.stdout.strip().split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Only check file lines where the filename is exactly kubeconfig
                if line.startswith('-') and "/host/etc/kubernetes/kubelet/config" in line:
                    found_kubeconfig = True
                    parts = line.split()
                    if len(parts) >= 9:
                        owner = parts[2]
                        group = parts[3]
                        full_path = parts[8]
                        
                        # Check if owner and group are root
                        if owner != "root" or group != "root": 
                            node_non_compliant_files.append(full_path)
            
            if not found_kubeconfig:
                print(f"Node {node_name} has no config file")
            
            elif not node_non_compliant_files:
                non_compliant_files[node_name] = node_non_compliant_files
        
        except Exception as e:
            print(f"Error checking node {node_name}: {str(e)}")
            continue
            
        finally:
            # 4. Clean up temporary files, remove Pod
            
            delete_cmd = "kubectl delete pod file-check --ignore-not-found"
            subprocess.run(delete_cmd, shell=True, check=True)

            wait_cmd = "kubectl wait --for=delete pod/file-check --timeout=60s || true"
            subprocess.run(wait_cmd, shell=True)

            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
        
    if non_compliant_files:
            result['compliant'] = False
            result['details'] = non_compliant_files
    else:
            result['compliant'] = True
    
    print("CIS 3.1.4 Scan Completed")
    return result

# 3.2.1 Ensure that the Anonymous Auth is Not Enabled
def cis_3_2_1(kube_config, cluster_name, region):
    result = {
        'check_id': "3.2.1",
        'title': "Ensure that the Anonymous Auth is Not Enabled",
        'resource_id': cluster_name,
        'compliant': False,
        'details': []
    }

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)
    
    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region}",
        shell=True, check=True
    )

    proxy_port = 8080

    proxy_process = subprocess.Popen(
        ["kubectl", "proxy", f"--port={proxy_port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    time.sleep(2)

    non_compliant_nodes = {}

    try:
        if proxy_process.poll() is not None:
            _, err = proxy_process.communicate()
            print(f"Start kubectl proxy failed: {err.decode()}")
        else:
            nodes = api.list_node()
            for node in nodes.items:
                node_name = node.metadata.name
                configz_url = f"http://localhost:{proxy_port}/api/v1/nodes/{node_name}/proxy/configz"
                try:
                    response = requests.get(configz_url, timeout=10)
                    if response.status_code == 200:
                        config = response.json()
                        anonymous_auth = config.get("kubeletconfig", {}).get("authentication", {}).get("anonymous", {}).get("enabled")
                        if anonymous_auth:
                            non_compliant_nodes[node_name] = True

                except Exception as e:
                    print(f"Error checking node {node_name}: {str(e)}")

    finally:
        if proxy_process.poll() is None:
            proxy_process.terminate()
            proxy_process.wait(timeout=5)

    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True

    print("CIS 3.2.1 Scan Completed")
    return result

# 3.2.2 Ensure that the --authorization-mode argument is not set to AlwaysAllow
def cis_3_2_2(kube_config, cluster_name, region):
    result = {
        'check_id': "3.2.2",
        'title': "Ensure that the --authorization-mode argument is not set to AlwaysAllow",
        'resource_id': cluster_name,
        'compliant': False,
        'details': []
    }

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)
    
    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region}",
        shell=True, check=True)

    proxy_port = 8080

    proxy_process = subprocess.Popen(
        ["kubectl", "proxy", f"--port={proxy_port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    time.sleep(2)

    non_compliant_nodes = {}

    try:
        if proxy_process.poll() is not None:
            _, err = proxy_process.communicate()
            print(f"Start kubectl proxy failed: {err.decode()}")
        else:
            nodes = api.list_node()
            for node in nodes.items:
                node_name = node.metadata.name
                configz_url = f"http://localhost:{proxy_port}/api/v1/nodes/{node_name}/proxy/configz"
                try:
                    response = requests.get(configz_url, timeout=10)
                    if response.status_code == 200:
                        config = response.json()
                        webhook_enabled = config.get("kubeletconfig", {}).get("authentication", {}).get("webhook", {}).get("enabled")
                        if not webhook_enabled:
                            non_compliant_nodes[node_name] = True

                except Exception as e:
                    print(f"Error checking node {node_name}: {str(e)}")
                    
    finally:
        if proxy_process.poll() is None:
            proxy_process.terminate()
            proxy_process.wait(timeout=5)

    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True

    print("CIS 3.2.2 Scan Completed")
    return result

# 3.2.3 Ensure that a Client CA File is Configured
def cis_3_2_3(kube_config, cluster_name, region):
    result = {
        'check_id': "3.2.3",
        'title': "Ensure that a Client CA File is Configured",
        'resource_id': cluster_name,
        'compliant': False,
        'details': []
    }

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)
    
    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region}",
        shell=True, check=True
    )

    proxy_port = 8080

    proxy_process = subprocess.Popen(
        ["kubectl", "proxy", f"--port={proxy_port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    time.sleep(2)

    non_compliant_nodes = {}

    try:
        if proxy_process.poll() is not None:
            _, err = proxy_process.communicate()
            print(f"Start kubectl proxy failed: {err.decode()}")
        else:
            nodes = api.list_node()
            for node in nodes.items:
                node_name = node.metadata.name
                configz_url = f"http://localhost:{proxy_port}/api/v1/nodes/{node_name}/proxy/configz"
                try:
                    response = requests.get(configz_url, timeout=10)
                    if response.status_code == 200:
                        config = response.json()
                        client_ca_file = config.get("kubeletconfig", {}).get("authentication", {}).get("x509", {}).get("clientCAFile")
                        if not client_ca_file:
                            non_compliant_nodes[node_name] = True
                except Exception as e:
                    print(f"Error checking node {node_name}: {str(e)}")

    finally:
        if proxy_process.poll() is None:
            proxy_process.terminate()
            proxy_process.wait(timeout=5)

    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True

    print("CIS 3.2.3 Scan Completed")
    return result

# 3.2.4 Ensure that the --read-only-port is disabled
def cis_3_2_4(kube_config, cluster_name, region):

    result = {
        'check_id': "3.2.4",
        'title': "Ensure that the --read-only-port is disabled",
        'resource_id': cluster_name,
        'compliant': False,
        'details': {}
    }

    ec2 = boto3.client('ec2', region_name=region)
    ssm = boto3.client('ssm', region_name=region)
    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)

    # Get all nodes from Kubernetes API
    nodes = api.list_node()
    non_compliant_nodes = {}

    for node in nodes.items:
        node_name = node.metadata.name
        try:
            # Step 1: Get EC2 instance ID from node_name
            response = ec2.describe_instances(
                Filters=[{"Name": "private-dns-name", "Values": [node_name]}]
            )
            instance_id = response["Reservations"][0]["Instances"][0]["InstanceId"]

            ssm_info = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])
            if not ssm_info['InstanceInformationList']:
                print(f"Instance {node_name} is not managed by SSM")
                continue
        except (IndexError, KeyError):
            print(f"Failed to find instance ID for node name '{node_name}'")
            continue

        # Step 2: Execute ps command to find kubelet config path
        ps_command = 'ps -ef | grep kubelet'
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': [ps_command]},
        )
        command_id = response['Command']['CommandId']
        time.sleep(2)

        output_ps = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id,
        )
        stdout = output_ps.get("StandardOutputContent", "")
        config_path = None
        for part in stdout.split():
            if part.startswith('--config'):
                if '=' in part:
                    config_path = part.split('=')[1]
                else:
                    idx = stdout.split().index(part)
                    config_path = stdout.split()[idx + 1]
                break

        if not config_path:
            print(f"Failed to find kubelet config path on node {node_name}")
            continue

        # Step 3: Read the config file
        cat_command = f"cat {config_path}"
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': [cat_command]},
        )
        command_id = response['Command']['CommandId']
        time.sleep(2)

        output_config = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id,
        )
        try:
            config_json = json.loads(output_config.get("StandardOutputContent", "{}"))
            ro_port = config_json.get("readOnlyPort", 10255)
            if ro_port != 0:
                non_compliant_nodes[node_name] = False
        except json.JSONDecodeError:
            print(f"Failed to parse kubelet config on node {node_name}")

    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True

    print("CIS 3.2.4 Scan Completed")
    return result

# 3.2.5 Ensure that the --streaming-connection-idle-timeout argument is not set to 0
def cis_3_2_5(kube_config, cluster_name, region):
    result = {
        'check_id': "3.2.5",
        'title': "Ensure that the streamingConnectionIdleTimeout argument is not set to 0",
        'resource_id': cluster_name,
        'compliant': False,
        'details': {}
    }

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)

    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region}",
        shell=True, check=True
    )

    proxy_port = 8001
    proxy_process = subprocess.Popen(
        ["kubectl", "proxy", f"--port={proxy_port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    time.sleep(5)
    non_compliant_nodes = {}

    try:
        if proxy_process.poll() is not None:
            _, err = proxy_process.communicate()
            print(f"Start kubectl proxy failed: {err.decode()}")
        else:
            nodes = api.list_node()
            for node in nodes.items:
                node_name = node.metadata.name
                url = f"http://localhost:{proxy_port}/api/v1/nodes/{node_name}/proxy/configz"
                try:
                    res = requests.get(url, timeout=10)
                    if res.status_code == 200:
                        config = res.json()
                        timeout_val = config.get("kubeletconfig", {}).get("streamingConnectionIdleTimeout", "")
                        if timeout_val in ("0", "0s", "0m0s", "0h0m0s", ""):
                            non_compliant_nodes[node_name] = False

                except Exception as e:
                    print(f"Error checking node {node_name}: {str(e)}")
    finally:
        if proxy_process.poll() is None:
            proxy_process.terminate()
            proxy_process.wait(timeout=5)

    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True

    print("CIS 3.2.5 Scan Completed")
    return result

# 3.2.6 Ensure that the --make-iptables-util-chains argument is set to true
def cis_3_2_6(kube_config, cluster_name, region):
    result = {
        'check_id': "3.2.6",
        'title': "Ensure that the --make-iptables-util-chains argument is set to true",
        'resource_id': cluster_name,
        'compliant': False,
        'details': {}
    }

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)

    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region}",
        shell=True, check=True
    )

    proxy_port = 8001
    proxy_process = subprocess.Popen(
        ["kubectl", "proxy", f"--port={proxy_port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    time.sleep(5)
    non_compliant_nodes = {}

    try:
        if proxy_process.poll() is not None:
            _, err = proxy_process.communicate()
            print(f"Start kubectl proxy failed: {err.decode()}")
        else:
            nodes = api.list_node()
            for node in nodes.items:
                node_name = node.metadata.name
                url = f"http://localhost:{proxy_port}/api/v1/nodes/{node_name}/proxy/configz"
                try:
                    res = requests.get(url, timeout=10)
                    if res.status_code == 200:
                        config = res.json()
                        make_iptables_util_chains = config.get("kubeletconfig", {}).get("makeIPTablesUtilChains")
                        # Check if the parameter is set to true
                        if make_iptables_util_chains is not True:
                            non_compliant_nodes[node_name] = False
                except Exception as e:
                    print(f"Error checking node {node_name}: {str(e)}")
    finally:
        if proxy_process.poll() is None:
            proxy_process.terminate()
            proxy_process.wait(timeout=5)

    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True

    print("CIS 3.2.6 Scan Completed")
    return result

# 3.2.7 Ensure that the --eventRecordQPS argument is set to 0 or a level which ensures appropriate event capture (Automated)
def cis_3_2_7(kube_config, cluster_name, region):
    result = {
        'check_id': "3.2.7",
        'title': "Ensure that the --eventRecordQPS argument is set to 0 or a level which ensures appropriate event capture",
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    ec2 = boto3.client('ec2', region_name=region)
    ssm = boto3.client('ssm', region_name=region)
    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)

    nodes = api.list_node()
    non_compliant_nodes = {}

    for node in nodes.items:
        node_name = node.metadata.name
        try:
            # Get EC2 instance ID
            ec2_response = ec2.describe_instances(
                Filters=[{"Name": "private-dns-name", "Values": [node_name]}]
            )
            instance_id = ec2_response["Reservations"][0]["Instances"][0]["InstanceId"]
        except Exception as e:
            print(f"[ERROR] Failed to get EC2 instance ID for node {node_name}: {str(e)}")
            continue

        try:
            # Get kubelet config content through SSM
            cat_command = 'cat /etc/kubernetes/kubelet/kubelet-config.json'
            send_res = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={'commands': [cat_command]},
            )
            command_id = send_res['Command']['CommandId']
            time.sleep(2)

            output = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id,
            )
            stdout = output.get("StandardOutputContent", "")

            # Parse JSON and check eventRecordQPS
            config_json = json.loads(stdout)
            qps = config_json.get("eventRecordQPS", 5)  # Default to 5

            if qps == 0:
                non_compliant_nodes[node_name] = False
            elif not isinstance(qps, int) or qps < 0:
                non_compliant_nodes[node_name] = False
            # else: compliant, not recorded
        except Exception as e:
            print(f"[ERROR] Error checking node {node_name}: {str(e)}")
    
    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True

    print("CIS 3.2.7 Scan Completed")
    return result

def cis_3_2_8(kube_config, cluster_name, region):
    result = {
        'check_id': "3.2.8",
        'title': "Ensure that the --rotate-certificates argument is not present or is set to true",
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    ec2 = boto3.client('ec2', region_name=region)
    ssm = boto3.client('ssm', region_name=region)
    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)

    nodes = api.list_node()
    non_compliant_nodes = {}

    for node in nodes.items:
        node_name = node.metadata.name
        try:
            # Get EC2 instance ID
            ec2_response = ec2.describe_instances(
                Filters=[{"Name": "private-dns-name", "Values": [node_name]}]
            )
            instance_id = ec2_response["Reservations"][0]["Instances"][0]["InstanceId"]
        except Exception as e:
            print(f"[ERROR] Failed to get EC2 instance ID for node {node_name}: {str(e)}")
            continue

        try:
            # Read kubelet config content
            cat_command = 'cat /etc/kubernetes/kubelet/kubelet-config.json'
            send_res = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={'commands': [cat_command]},
            )
            command_id = send_res['Command']['CommandId']
            time.sleep(2)

            output = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id,
            )
            stdout = output.get("StandardOutputContent", "")

            config_json = json.loads(stdout)
            value = config_json.get("rotateCertificates", None)

            if value is False:
                non_compliant_nodes[node_name] = False
            # value is True or None (not present) => compliant
        except Exception as e:
            print(f"[ERROR] Error checking node {node_name}: {str(e)}")

    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True

    print("CIS 3.2.8 Scan Completed")
    return result

def cis_3_2_9(kube_config, cluster_name, region):
    result = {
        'check_id': "3.2.9",
        'title': "Ensure that the RotateKubeletServerCertificate feature gate is enabled",
        'resource_id': cluster_name,
        'compliant': False,
        'details': {}
    }

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)

    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region}",
        shell=True, check=True
    )

    proxy_port = 8001
    proxy_process = subprocess.Popen(
        ["kubectl", "proxy", f"--port={proxy_port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    time.sleep(5)
    non_compliant_nodes = {}

    try:
        if proxy_process.poll() is not None:
            _, err = proxy_process.communicate()
            print(f"Start kubectl proxy failed: {err.decode()}")
        else:
            nodes = api.list_node()
            for node in nodes.items:
                node_name = node.metadata.name
                url = f"http://localhost:{proxy_port}/api/v1/nodes/{node_name}/proxy/configz"
                try:
                    res = requests.get(url, timeout=10)
                    if res.status_code == 200:
                        config = res.json()
                        feature_gates = config.get("kubeletconfig", {}).get("featureGates", {})
                        rotate_enabled = feature_gates.get("RotateKubeletServerCertificate")

                        if rotate_enabled is not True:
                            non_compliant_nodes[node_name] = False 
                except Exception as e:
                    print(f"Error checking node {node_name}: {str(e)}")
    finally:
        if proxy_process.poll() is None:
            proxy_process.terminate()
            proxy_process.wait(timeout=5)

    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True

    print("CIS 3.2.9 Scan Completed")
    return result
