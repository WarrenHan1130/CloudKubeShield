import kubernetes
import subprocess
import tempfile
import json
import time
import requests
import os

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
            subprocess.run("kubectl wait --for=condition=Ready pod/file-check --timeout=60s",
                         shell=True, check=True)
            
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
            subprocess.run("kubectl wait --for=condition=Ready pod/file-check --timeout=60s",
                         shell=True, check=True)
            
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
    
    nodes = api.list_node()
    non_compliant_nodes = {} 
    for node in nodes.items:
        node_name = node.metadata.name

        subprocess.run(
            f"aws eks update-kubeconfig --name {cluster_name} --region {region}",
            shell=True, check=True)
    
        proxy_port = 8080

        # Initialize proxy process
        proxy_process = subprocess.Popen(
            ["kubectl", "proxy", f"--port={proxy_port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    
        time.sleep(2)
    
        try:
            if proxy_process.poll() is not None:
                _, err = proxy_process.communicate()
                print(f"Start kubectl proxy failed: {err.decode()}")
                
            configz_url = f"http://localhost:8080/api/v1/nodes/{node_name}/proxy/configz"
            response = requests.get(configz_url, timeout=10)

            if response.status_code == 200:
                config = response.json()

                auth_config = config.get("kubeletconfig", {}).get("authentication", {})
                anonymous_auth = auth_config.get("anonymous", {}).get("enabled")

            else:
                non_compliant_nodes[node_name] = anonymous_auth

        except Exception:
            print(f"Error checking node {node_name}: {str(e)}")
        finally:
        # Shutdown kubectl proxy
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
       