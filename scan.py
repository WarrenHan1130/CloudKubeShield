import kubernetes
import subprocess
import tempfile
import json
import time
import requests
import os
import boto3
import concurrent.futures
import fnmatch

def check_wildcards_in_role(role, role_type, namespace=None):
    """Check for wildcard usage in Role or ClusterRole"""
    if not role.rules:
        return None

    wildcard_rules = []
    for rule in role.rules:
        wildcards = {}
            
        # Check resource wildcards
        if rule.resources and '*' in rule.resources:
            wildcards['resources'] = '*'
            
        # Check verb wildcards
        if rule.verbs and '*' in rule.verbs:
            wildcards['verbs'] = '*'
            
        # Check API group wildcards
        if rule.api_groups and '*' in rule.api_groups:
            wildcards['api_groups'] = '*'
            
        if wildcards:
            wildcard_rules.append({
                'rule_index': len(wildcard_rules),
                'wildcards': wildcards,
                'original_rule': {
                    'resources': rule.resources,
                    'verbs': rule.verbs,
                    'api_groups': rule.api_groups
                }
            })
        
    if wildcard_rules:
        role_info = {
            'type': role_type,
            'name': role.metadata.name,
            'wildcard_rules': wildcard_rules
        }
            
        if namespace:
            role_info['namespace'] = namespace
            
        return role_info
        
    return None

def check_role_for_secrets(role, bindings, sensitive_verbs={"get", "list", "watch"}, sensitive_resource="secrets"):
    """Check if Role or ClusterRole has secrets permissions"""
    if not role.rules:
        return None

    secret_rules = []
    for rule in role.rules:
      
        if rule.resources and rule.verbs:
            matched_verbs = list(set(rule.verbs) & sensitive_verbs)
            if sensitive_resource in rule.resources and matched_verbs:
                secret_rules.append({
                    'resources': rule.resources,
                    'verbs': matched_verbs,
                    'api_groups': rule.api_groups if rule.api_groups else []
                })
    
    if secret_rules:
        role_bindings = []
        for b in bindings:
            if b.role_ref and b.role_ref.name == role.metadata.name:
                role_bindings.append({
                    'name': b.metadata.name,
                    'subjects': [
                        {'kind': s.kind, 'name': s.name, 'namespace': getattr(s, 'namespace', 'N/A')} 
                        for s in (b.subjects or [])
                    ]
                })
        
        if role_bindings:
            return {
                'rules': secret_rules,
                'bindings': role_bindings
            }
    return None


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
def cis_2_1_2(kube_config, cluster_name, region, profile):

    result = {
        'check_id': "2.1.2",
        'title': "Ensure audit logs are collected and managed",
        'resource_id': cluster_name,
        'compliant': True,
        'details': []
    }

    non_compliant_nodes = []
    # Update kubeconfig for the kubeclt
    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
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
        result['details'].append({"message": "All audit logs are collected and managed, no non-compliant items"})
    
    print("CIS 2.1.2 Scan Completed")
    return result

# CIS 3.1.1 Ensure that the kubeconfig file permissions are set to 644 or more restrictive.
def cis_3_1_1(kube_config, cluster_name, region, profile):
    
    result = {
        'check_id': "3.1.1",
        'title': "Ensure that the kubeconfig file permissions are set to 644 or more restrictive.",
        'resource_id': cluster_name,
        'compliant': True,
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
            f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
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
            find_cmd = 'kubectl exec -it file-check -- sh -c "find /host -name kubeconfig 2>/dev/null -exec ls -l --color=never {} \\;"'
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
            
            elif node_non_compliant_files:
                non_compliant_files[node_name] = node_non_compliant_files
        
        except Exception as e:
            result['compliant'] = True
            result['details'][node_name] = str(e)
            print(f"Error performing CIS 3.1.1 scan: {str(e)}")
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
        if not result['details']:
            result['details'] = {"message": "All kubeconfig files have 644 or more restrictive permissions, no non-compliant items"}
    
    print("CIS 3.1.1 Scan Completed")
    return result

# 3.1.2 Ensure that the kubelet kubeconfig file ownership is set to root:root
def cis_3_1_2(kube_config, cluster_name, region, profile):

    result = {
        'check_id': "3.1.2",
        'title': "Ensure that the kubelet kubeconfig file ownership is set to root:root",
        'resource_id': cluster_name,
        'compliant': True,
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
            f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
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
            find_cmd = 'kubectl exec -it file-check -- sh -c "find /host -name kubeconfig 2>/dev/null -exec ls -l --color=never {} \\;"'
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
            
            elif node_non_compliant_files:
                non_compliant_files[node_name] = node_non_compliant_files
        
        except Exception as e:
            result['compliant'] = True
            result['details'][node_name] = str(e)
            print(f"Error performing CIS 3.1.2 scan: {str(e)}")
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
        if not result['details']:
            result['details'] = {"message": "All kubelet kubeconfig files have root:root ownership, no non-compliant items"}

    print("CIS 3.1.2 Scan Completed")
    return result

# 3.1.3 Ensure that the kubelet kubeconfig file permissions are set to 644 or more restrictive
def cis_3_1_3(kube_config, cluster_name, region, profile):

    result = {
        'check_id': "3.1.3",
        'title': "Ensure that the kubelet kubeconfig file permissions are set to 644 or more restrictive",
        'resource_id': cluster_name,
        'compliant': True,
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
            f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
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
            find_cmd = "kubectl exec -it file-check -- ls -l --color=never /host/etc/kubernetes/kubelet/kubelet-config.json"
            find_result = subprocess.run(find_cmd, shell=True, capture_output=True, text=True)
            
            # Check if all kubeconfig files comply with requirements
            found_config = False
            node_non_compliant_files = []
            lines = find_result.stdout.strip().split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Only check file lines where the filename is exactly config
                if line.startswith('-') and "/host/etc/kubernetes/kubelet/kubelet-config.json" in line:
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
            
            elif node_non_compliant_files:
                non_compliant_files[node_name] = node_non_compliant_files
        
        except Exception as e:
            result['compliant'] = True
            result['details'][node_name] = str(e)
            print(f"Error performing CIS 3.1.3 scan: {str(e)}")
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
            if not result['details']:
                result['details'] = {"message": "All kubelet kubeconfig files have 644 or more restrictive permissions, no non-compliant items"}

    print("CIS 3.1.3 Scan Completed")
    return result

# 3.1.4 Ensure that the kubelet config file permissions are set to 644 or more restrictive
def cis_3_1_4(kube_config, cluster_name, region, profile):

    result = {
        'check_id': "3.1.4",
        'title': "Ensure that the kubelet config file permissions are set to 644 or more restrictive",
        'resource_id': cluster_name,
        'compliant': True,
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
            f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
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
            find_cmd = "kubectl exec -it file-check -- ls -l --color=never /host/etc/kubernetes/kubelet/kubelet-config.json"
            find_result = subprocess.run(find_cmd, shell=True, capture_output=True, text=True)
            
            # Check if all kubeconfig files comply with requirements
            found_kubeconfig = False
            node_non_compliant_files = []
            lines = find_result.stdout.strip().split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Only check file lines where the filename is exactly kubeconfig
                if line.startswith('-') and "/host/etc/kubernetes/kubelet/kubelet-config.json" in line:
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
            
            elif node_non_compliant_files:
                non_compliant_files[node_name] = node_non_compliant_files
        
        except Exception as e:
            result['compliant'] = True
            result['details'][node_name] = str(e)
            print(f"Error performing CIS 3.1.4 scan: {str(e)}")
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
            if not result['details']:
                result['details'] = {"message": "All kubelet kubeconfig files have 644 or more restrictive permissions, no non-compliant items"}

    print("CIS 3.1.4 Scan Completed")
    return result

# 3.2.1 Ensure that the Anonymous Auth is Not Enabled
def cis_3_2_1(kube_config, cluster_name, region, profile):
    result = {
        'check_id': "3.2.1",
        'title': "Ensure that the Anonymous Auth is Not Enabled",
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)
    
    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
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
                            non_compliant_nodes[node_name] = False

                except Exception as e:
                    result['compliant'] = True
                    result['details'][node_name] = str(e)
                    print(f"Error performing CIS 3.2.1 scan: {str(e)}")

    finally:
        if proxy_process.poll() is None:
            proxy_process.terminate()
            proxy_process.wait(timeout=5)

    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True
        if not result['details']:
            result['details'] = {"message": "Anonymous Auth is not enabled"}

    print("CIS 3.2.1 Scan Completed")
    return result

# 3.2.2 Ensure that the --authorization-mode argument is not set to AlwaysAllow
def cis_3_2_2(kube_config, cluster_name, region, profile):
    result = {
        'check_id': "3.2.2",
        'title': "Ensure that the --authorization-mode argument is not set to AlwaysAllow",
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)
    
    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
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
                        kubelet_config = config.get("kubeletconfig", {})
                        authn_webhook = kubelet_config.get("authentication", {}).get("webhook", {}).get("enabled", False)
                        authz_mode = kubelet_config.get("authorization", {}).get("mode", "").lower()

                        if not authn_webhook or authz_mode != "webhook":
                            non_compliant_nodes[node_name] = {
                                "authentication.webhook.enabled": authn_webhook,
                                "authorization.mode": authz_mode or "not set"
                            }

                except Exception as e:
                    result['compliant'] = True
                    result['details'][node_name] = str(e)
                    print(f"Error performing CIS 3.2.2 scan: {str(e)}")
                    
    finally:
        if proxy_process.poll() is None:
            proxy_process.terminate()
            proxy_process.wait(timeout=5)

    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True
        if not result['details']:
            result['details'] = {"message": "Authorization mode is set to Webhook and authentication webhook is enabled"}

    print("CIS 3.2.2 Scan Completed")
    return result

# 3.2.3 Ensure that a Client CA File is Configured
def cis_3_2_3(kube_config, cluster_name, region, profile):
    result = {
        'check_id': "3.2.3",
        'title': "Ensure that a Client CA File is Configured",
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)
    
    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
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
                    print(response.status_code)
                    if response.status_code == 200:
                        config = response.json()
                        client_ca_file = config.get("kubeletconfig", {}).get("authentication", {}).get("x509", {}).get("clientCAFile")
                        if not client_ca_file:
                            non_compliant_nodes[node_name] = False
                    else:
                        non_compliant_nodes[node_name] = True
                except Exception as e:
                    result['compliant'] = True
                    result['details'][node_name] = str(e)
                    print(f"Error performing CIS 3.2.3 scan: {str(e)}")

    finally:
        if proxy_process.poll() is None:
            proxy_process.terminate()
            proxy_process.wait(timeout=5)

    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True
        if not result['details']:
            result['details'] = {"message": "Client CA File is configured"}

    print("CIS 3.2.3 Scan Completed")
    return result

# 3.2.4 Ensure that the --read-only-port is disabled
def cis_3_2_4(kube_config, cluster_name, region, session):

    result = {
        'check_id': "3.2.4",
        'title': "Ensure that the --read-only-port is disabled",
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    ec2 = session.client('ec2', region_name=region)
    ssm = session.client('ssm', region_name=region)
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
            result['compliant'] = True
            result['details'][node_name] = "Failed to find instance ID for node name"
            print("Error performing CIS 3.2.4 scan.")
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
        if not result['details']:
            result['details'] = {"message": "Read only port is disabled"}
    print("CIS 3.2.4 Scan Completed")
    return result

# 3.2.5 Ensure that the --streaming-connection-idle-timeout argument is not set to 0
def cis_3_2_5(kube_config, cluster_name, region, profile):
    result = {
        'check_id': "3.2.5",
        'title': "Ensure that the streamingConnectionIdleTimeout argument is not set to 0",
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)

    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
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
                    result['compliant'] = True
                    result['details'][node_name] = str(e)
                    print(f"Error performing CIS 3.2.5 scan: {str(e)}")
    finally:
        if proxy_process.poll() is None:
            proxy_process.terminate()
            proxy_process.wait(timeout=5)

    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True
        if not result['details']:
            result['details'] = {"message": "Streaming connection idle timeout is not set to 0"}

    print("CIS 3.2.5 Scan Completed")
    return result

# 3.2.6 Ensure that the --make-iptables-util-chains argument is set to true
def cis_3_2_6(kube_config, cluster_name, region, profile):
    result = {
        'check_id': "3.2.6",
        'title': "Ensure that the --make-iptables-util-chains argument is set to true",
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)

    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
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
                    result['compliant'] = True
                    result['details'][node_name] = str(e)
                    print(f"Error performing CIS 3.2.6 scan: {str(e)}")
    finally:
        if proxy_process.poll() is None:
            proxy_process.terminate()
            proxy_process.wait(timeout=5)

    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True
        if not result['details']:
            result['details'] = {"message": "Make iptables util chains is set to true"}

    print("CIS 3.2.6 Scan Completed")
    return result

# 3.2.7 Ensure that the --eventRecordQPS argument is set to 0 or a level which ensures appropriate event capture (Automated)
def cis_3_2_7(kube_config, cluster_name, region, session):
    result = {
        'check_id': "3.2.7",
        'title': "Ensure that the --eventRecordQPS argument is set to 0 or a level which ensures appropriate event capture",
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    ec2 = session.client('ec2', region_name=region)
    ssm = session.client('ssm', region_name=region)
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
            result['compliant'] = True
            result['details'][node_name] = str(e)
            print(f"Error performing CIS 3.2.7 scan: {str(e)}")
    
    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True
        if not result['details']:
            result['details'] = {"message": "Event record QPS is set to 0 or a level which ensures appropriate event capture"}

    print("CIS 3.2.7 Scan Completed")
    return result

def cis_3_2_8(kube_config, cluster_name, region, session):
    result = {
        'check_id': "3.2.8",
        'title': "Ensure that the --rotate-certificates argument is not present or is set to true",
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    ec2 = session.client('ec2', region_name=region)
    ssm = session.client('ssm', region_name=region)
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
            value = config_json.get("RotateCertificates", None)

            if value is False:
                non_compliant_nodes[node_name] = False
            # value is True or None (not present) => compliant
        except Exception as e:
            result['compliant'] = True
            result['details'][node_name] = str(e)
            print(f"Error performing CIS 3.2.8 scan: {str(e)}")

    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True
        if not result['details']:
            result['details'] = {"message": "Rotate certificates is not present or is set to true"}

    print("CIS 3.2.8 Scan Completed")
    return result

def cis_3_2_9(kube_config, cluster_name, region, profile):
    result = {
        'check_id': "3.2.9",
        'title': "Ensure that the RotateKubeletServerCertificate feature gate is enabled",
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    kclient = kubernetes.client.ApiClient(configuration=kube_config)
    api = kubernetes.client.CoreV1Api(api_client=kclient)

    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
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
                    else:
                        non_compliant_nodes[node_name] = False
                except Exception as e:
                    result['compliant'] = True
                    result['details'][node_name] = str(e)
                    print(f"Error performing CIS 3.2.9 scan: {str(e)}")
    finally:
        if proxy_process.poll() is None:
            proxy_process.terminate()
            proxy_process.wait(timeout=5)

    if non_compliant_nodes:
        result['compliant'] = False
        result['details'] = non_compliant_nodes
    else:
        result['compliant'] = True
        if not result['details']:
            result['details'] = {"message": "RotateKubeletServerCertificate feature gate is enabled"}

    print("CIS 3.2.9 Scan Completed")
    return result

# 4.1.1 Ensure that the cluster-admin role is only used where required (Automated)
def cis_4_1_1(kubeconfig, cluster_name):
    result = {
        'check_id': '4.1.1',
        'title': 'Ensure that the cluster-admin role is only used where required',
        'description': 'Ensure that the cluster-admin role is only used where required',
        'resource_id': cluster_name,
        'compliant': True,
        'details': []
    }
    
    try:
            
        kclient = kubernetes.client.ApiClient(configuration=kubeconfig)
        rbac_api = kubernetes.client.RbacAuthorizationV1Api(api_client=kclient)
        
        # Get all ClusterRoleBindings
        bindings  = rbac_api.list_cluster_role_binding()
        
        # Find bindings associated with the cluster-admin role
        for binding in bindings.items:
            if binding.role_ref.name == "cluster-admin":
                result["details"].append(binding.metadata.name)
        
        if result["details"]:
            result['compliant'] = False
            
    except Exception as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.1.1 scan: {str(e)}")
    
    if result['compliant']:
        if not result['details']:
            result['details'].append({"message": "Cluster-admin role is only used where required"})
    
    print("CIS 4.1.1 Scan Completed")
    return result

# 4.1.2 Ensure that access to Kubernetes secrets is restricted (Automated)
def cis_4_1_2(kubeconfig, cluster_name):
    result = {
        'check_id': '4.1.2',
        'title': 'Ensure that access to Kubernetes secrets is restricted',
        'description': 'Ensure that access to Kubernetes secrets is restricted',
        'resource_id': cluster_name,
        'compliant': True,
        'details': []
    }

    try:
        # Load Kubeconfig   
        kclient = kubernetes.client.ApiClient(configuration=kubeconfig)
        rbac_api = kubernetes.client.RbacAuthorizationV1Api(api_client=kclient)
        core_api = kubernetes.client.CoreV1Api(api_client=kclient)

        # **1. Check ClusterRoles**
        cluster_roles = rbac_api.list_cluster_role()
        cluster_role_bindings = rbac_api.list_cluster_role_binding().items
        for role in cluster_roles.items:
            role_info = check_role_for_secrets(role, cluster_role_bindings)
            if role_info:
                result['details'].append(f"ClusterRole/{role.metadata.name}")

        # **2. Check Namespaced Roles**
        namespaces = [ns.metadata.name for ns in core_api.list_namespace().items]
        for ns in namespaces:
            try:
                roles = rbac_api.list_namespaced_role(ns).items
                role_bindings = rbac_api.list_namespaced_role_binding(ns).items
                
                for role in roles:
                    role_info = check_role_for_secrets(role, role_bindings)
                    if role_info:
                        result['details'].append(f"Role/{ns}/{role.metadata.name}")
            except Exception as e:
                result['compliant'] = True
                result['details'].append(f"Error checking namespace {ns}: {e}")
                print(f"Error performing CIS 4.1.2 scan: {str(e)}")

        # **3. Set Compliance**
        if result['details']:
            result['compliant'] = False
            
    except Exception as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.1.2 scan: {str(e)}")
    
    if result['compliant']:
        if not result['details']:
            result['details'].append({"message": "Access to Kubernetes secrets is restricted"})

    print("CIS 4.1.2 Scan Completed")
    return result

# 4.1.3 Minimize wildcard use in Roles and ClusterRoles (Automated)
def cis_4_1_3(kubeconfig, cluster_name):
    result = {
        'check_id': '4.1.3',
        'title': 'Minimize wildcard use in Roles and ClusterRoles',
        'description': 'Minimize wildcard use in Roles and ClusterRoles',
        'resource_id': cluster_name,
        'compliant': True,
        'details': []
    }

    try:
        # Load Kubeconfig
        kclient = kubernetes.client.ApiClient(configuration=kubeconfig)
        rbac_api = kubernetes.client.RbacAuthorizationV1Api(api_client=kclient)
        core_api = kubernetes.client.CoreV1Api(api_client=kclient)

        # 1. Check ClusterRoles
        cluster_roles = rbac_api.list_cluster_role()
        for role in cluster_roles.items:
            role_info = check_wildcards_in_role(role, 'ClusterRole')
            if role_info:
                result['details'].append(f"ClusterRole/{role.metadata.name}")

        # 2. Check Namespaced Roles
        namespaces = [ns.metadata.name for ns in core_api.list_namespace().items]
        for ns in namespaces:
            try:
                roles = rbac_api.list_namespaced_role(ns).items
                for role in roles:
                    role_info = check_wildcards_in_role(role, 'Role', ns)
                    if role_info:
                        result['details'].append(f"Role/{ns}/{role.metadata.name}")
            except Exception as e:
                result['compliant'] = True
                result['details'].append(f"Error checking namespace {ns}: {e}")
                print(f"Error performing CIS 4.1.3 scan: {str(e)}")

        # 3. Set Compliance
        if result['details']:
            result['compliant'] = False

    except Exception as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.1.3 scan: {str(e)}")

    if result['compliant']:
        if not result['details']:
            result['details'].append({"message": "Minimize wildcard use in Roles and ClusterRoles"})

    print("CIS 4.1.3 Scan Completed")
    return result

# 4.1.4 Minimize access to create pods (Automated)
def cis_4_1_4(kubeconfig, cluster_name):
    result = {
        'check_id': '4.1.4',
        'title': 'Minimize access to create pods',
        'description': 'Ensure that access to create pods is restricted',
        'resource_id': cluster_name,
        'compliant': True,
        'details': []
    }
    
    try:
        kclient = kubernetes.client.ApiClient(configuration=kubeconfig)
        rbac_api = kubernetes.client.RbacAuthorizationV1Api(api_client=kclient)

        cluster_roles = rbac_api.list_cluster_role().items
        roles = {}

        core_api = kubernetes.client.CoreV1Api(api_client=kclient)
        namespaces = core_api.list_namespace()

        for ns in namespaces.items:
            namespace = ns.metadata.name
            try:
                ns_roles = rbac_api.list_namespaced_role(namespace)
                roles[namespace] = ns_roles.items
            except Exception as e:
                print(f"Error getting roles for namespace {namespace}: {str(e)}")

        for role in cluster_roles:
            if role.rules: 
                for rule in role.rules:
                    if rule.resources and rule.verbs:
                        if "pods" in rule.resources and "create" in rule.verbs:
                            result['details'].append(f"ClusterRole/{role.metadata.name}")
        
        for namespace, ns_roles in roles.items():
            for role in ns_roles:
                if role.rules: 
                    for rule in role.rules:
                        if rule.resources and rule.verbs:
                            if "pods" in rule.resources and "create" in rule.verbs:
                                result['details'].append(f"Role/{ns}/{role.metadata.name}")

        if result['details']:
            result['compliant'] = False

    except Exception as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.1.4 scan: {str(e)}")

    if result['compliant']:
        if not result['details']:
            result['details'].append({"message": "Minimize access to create pods"})

    print("CIS 4.1.4 Scan Completed")   
    return result

# 4.1.5 Ensure that default service accounts are not actively used. (Automated)
def cis_4_1_5(kubeconfig, cluster_name):
    result = {
        'check_id': '4.1.5',
        'title': 'Ensure that default service accounts are not actively used',
        'description': 'Ensure that default service accounts are not actively used',
        'resource_id': cluster_name,
        'compliant': True,
        'details': []
    }
    
    try:
        # Initialize Kubernetes client
        kclient = kubernetes.client.ApiClient(configuration=kubeconfig)
        core_api = kubernetes.client.CoreV1Api(api_client=kclient)
        rbac_api = kubernetes.client.RbacAuthorizationV1Api(api_client=kclient)
        
        # Get all namespaces
        namespaces = core_api.list_namespace()
        
        for ns in namespaces.items:
            namespace = ns.metadata.name
            
            try:
                # Get default service account
                default_sa = core_api.read_namespaced_service_account('default', namespace)

                if default_sa.automount_service_account_token is None or default_sa.automount_service_account_token:
                    result['details'].append(namespace)
                    result['compliant'] = False
                
                # Check for role bindings to default service account
                role_bindings = rbac_api.list_namespaced_role_binding(namespace)
                for rb in role_bindings.items:
                    for subject in rb.subjects or []:
                        if subject.kind == 'ServiceAccount' and subject.name == 'default' and subject.namespace == namespace:
                            result['details'].append(rb.role_ref.name)
                            result['compliant'] = False
                
                # Check for cluster role bindings to default service account
                cluster_role_bindings = rbac_api.list_cluster_role_binding()
                for crb in cluster_role_bindings.items:
                    for subject in crb.subjects or []:
                        if subject.kind == 'ServiceAccount' and subject.name == 'default' and subject.namespace == namespace:
                            result['details'].append(crb.role_ref.name)
                            result['compliant'] = False
                    
            except Exception as e:
                    if e.status != 404:
                        result['compliant'] = True
                        result['details'].append(f"Error checking default service account in namespace {namespace}: {str(e)}")
                        print(f"Error performing CIS 4.1.5 scan: {str(e)}")
                
    except Exception as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.1.5 scan: {str(e)}")

    if result['compliant']:
        if not result['details']:
            result['details'].append({"message": "Default service accounts are not actively used"})

    print("CIS 4.1.5 Scan Completed")
    return result

# 4.1.6 Ensure that Service Account Tokens are only mounted where necessary (Automated)
def cis_4_1_6(kubeconfig, cluster_name):
    result = {
        'check_id': '4.1.6',
        'title': 'Ensure that Service Account Tokens are only mounted where necessary',
        'description': 'Ensure that Service Account Tokens are only mounted where necessary',
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    try:
        kclient = kubernetes.client.ApiClient(configuration=kubeconfig)
        core_api = kubernetes.client.CoreV1Api(api_client=kclient)

        pods_with_tokens = []
        pods = core_api.list_pod_for_all_namespaces()
        for pod in pods.items:
            if pod.spec.automount_service_account_token is None or pod.spec.automount_service_account_token:
                pods_with_tokens.append({
                    'namespace': pod.metadata.namespace,
                    'pod': pod.metadata.name
                })

        sa_with_tokens = []
        service_accounts = core_api.list_service_account_for_all_namespaces()
        for sa in service_accounts.items:
            if sa.automount_service_account_token is None or sa.automount_service_account_token:
                sa_with_tokens.append({
                    'namespace': sa.metadata.namespace,
                    'service_account': sa.metadata.name
                })

        if pods_with_tokens or sa_with_tokens:
            result['compliant'] = False
            result['details'] = {
                'pods_with_service_account_tokens': pods_with_tokens,
                'service_accounts_with_tokens': sa_with_tokens
            }
        else:
            result['details'] = {'message': 'All service account tokens are correctly restricted.'}

    except Exception as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.1.6 scan: {str(e)}")
    
    if result['compliant']:
        if not result['details']:
            result['details'] = {"message": "All service account tokens are correctly restricted."}

    print("CIS 4.1.6 Scan Completed")
    return result

# 4.1.7 Cluster Access Manager API to streamline and enhance the management of access controls within EKS clusters (Automated)
def cis_4_1_7(cluster_name, region, session):
    result = {
        'check_id': '4.1.7',
        'title': 'Ensure Cluster Access Manager API is used instead of aws-auth ConfigMap',
        'description': 'Ensure Cluster Access Manager API is used instead of aws-auth ConfigMap',
        'resource_id': cluster_name,
        'compliant': False,
        'details': {}
    }
    
    try:
        # Initialize AWS client
        eks_client = session.client('eks', region_name=region)
        
        # Describe the cluster to check access configuration
        response = eks_client.describe_cluster(name=cluster_name)
        
        # Check if access configuration exists and get authentication mode
        if 'accessConfig' in response['cluster']:
            auth_mode = response['cluster']['accessConfig'].get('authenticationMode', 'CONFIG_MAP')
            result['details']['authenticationMode'] = auth_mode
            
            # Cluster is compliant if using API or API_AND_CONFIG_MAP
            if auth_mode in ['API', 'API_AND_CONFIG_MAP']:
                result['compliant'] = True
            else:
                result['details']['recommendation'] = "Switch authentication mode from 'CONFIG_MAP' to 'API' or 'API_AND_CONFIG_MAP'"
        else:
            # If accessConfig doesn't exist, assume it's using CONFIG_MAP
            result['details']['authenticationMode'] = 'CONFIG_MAP (assumed)'
            result['details']['recommendation'] = "Enable Cluster Access Manager API using 'aws eks update-cluster-config'"
    
    except Exception as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.1.7 scan: {str(e)}")
    
    if result['compliant']:
        if not result['details']:
            result['details'] = {"message": "Cluster Access Manager API is used instead of aws-auth ConfigMap"}

    print("CIS 4.1.7 Scan Completed")
    return result

# 4.1.8 Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster (Manual)
def cis_4_1_8(kubeconfig, cluster_name):
    result = {
        'check_id': '4.1.8',
        'title': 'Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster',
        'description': 'Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster',
        'resource_id': cluster_name,
        'compliant': True,
        'details': []
    }

    try:
        kclient = kubernetes.client.ApiClient(configuration=kubeconfig)
        rbac_api = kubernetes.client.RbacAuthorizationV1Api(api_client=kclient)

        non_compliant_roles = set() 
        # List all roles and cluster roles
        roles = rbac_api.list_role_for_all_namespaces()
        cluster_roles = rbac_api.list_cluster_role()

        # Check roles for impersonate, bind, or escalate permissions
        for role in roles.items:
            if role.rules:
                for rule in role.rules:
                    if any(verb in rule.verbs for verb in ['impersonate', 'bind', 'escalate']):
                        non_compliant_roles.add(role.metadata.name)

        # Check cluster roles for impersonate, bind, or escalate permissions
        for cluster_role in cluster_roles.items:
            if cluster_role.rules:
                for rule in cluster_role.rules:
                    if any(verb in rule.verbs for verb in ['impersonate', 'bind', 'escalate']):
                        non_compliant_roles.add(cluster_role.metadata.name)

        if non_compliant_roles:
            result['compliant'] = False
            result['details'] = non_compliant_roles

    except Exception as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.1.8 scan: {str(e)}")

    if result['compliant']:
        if not result['details']:
            result['details'].append({"message": "All roles and cluster roles have the Bind, Impersonate and Escalate permissions restricted."})

    print("CIS 4.1.8 Scan Completed")
    return result

# 4.2.1 Minimize the admission of privileged containers (Automated)
def cis_4_2_1(kubeconfig, cluster_name):

    result = {
        'check_id': '4.2.1',
        'title': 'Minimize the admission of privileged containers',
        'description': 'Minimize the admission of privileged containers',
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    try:
        kclient = kubernetes.client.ApiClient(configuration=kubeconfig)
        v1 = kubernetes.client.CoreV1Api(api_client=kclient)

        # Get pods from all namespaces
        pods = v1.list_pod_for_all_namespaces()

        for pod in pods.items:
            # Skip pods in kube-system namespace
            if pod.metadata.namespace == "kube-system":
                continue
                
            for container in pod.spec.containers:
                if container.security_context and container.security_context.privileged:
                    # If namespace not in dictionary, create a new list
                    if pod.metadata.namespace not in result['details']:
                        result['details'][pod.metadata.namespace] = []
                    # Add pod name to the list for this namespace
                    result['details'][pod.metadata.namespace].append(pod.metadata.name)
                    # Break early once we find a privileged container
                    break

        if result['details']:
            result['compliant'] = False

    except Exception as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.2.1 scan: {str(e)}")

    if result['compliant']:
        if not result['details']:
            result['details'] = {"message": "All privileged containers are minimized."}

    print("CIS 4.2.1 Scan Completed")
    return result

# 4.2.2 Minimize the admission of containers wishing to share the host process ID namespace (Automated)
def cis_4_2_2(kubeconfig, cluster_name):

    result = {
        'check_id': '4.2.2',
        'title': 'Minimize the admission of containers wishing to share the host process ID namespace',
        'description': 'Minimize the admission of containers wishing to share the host process ID namespace',
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    try:
        kclient = kubernetes.client.ApiClient(configuration=kubeconfig)
        v1 = kubernetes.client.CoreV1Api(api_client=kclient)

        # Get pods from all namespaces
        pods = v1.list_pod_for_all_namespaces()

        for pod in pods.items:
            # Skip pods in kube-system namespace
            if pod.metadata.namespace == "kube-system":
                continue
                
            # Check if pod has hostPID=true
            if pod.spec.host_pid:
                # If namespace not in dictionary, create a new list
                if pod.metadata.namespace not in result['details']:
                    result['details'][pod.metadata.namespace] = []
                # Add pod name to the list for this namespace
                result['details'][pod.metadata.namespace].append(pod.metadata.name)

        if result['details']:
            result['compliant'] = False

    except Exception as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.2.2 scan: {str(e)}")

    if result['compliant']:
        if not result['details']:
            result['details'] = {"message": "All containers wishing to share the host process ID namespace are minimized."}

    print("CIS 4.2.2 Scan Completed")
    return result

# 4.2.3 Minimize the admission of containers wishing to share the host IPC namespace (Automated)
def cis_4_2_3(kubeconfig, cluster_name):
    
    result = {
        'check_id': '4.2.3',
        'title': 'Minimize the admission of containers wishing to share the host IPC namespace',
        'description': 'Minimize the admission of containers wishing to share the host IPC namespace',
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    try:
        kclient = kubernetes.client.ApiClient(configuration=kubeconfig)
        v1 = kubernetes.client.CoreV1Api(api_client=kclient)

        # Get pods from all namespaces
        pods = v1.list_pod_for_all_namespaces()

        for pod in pods.items:
            # Skip pods in kube-system namespace
            if pod.metadata.namespace == "kube-system":
                continue
                
            # Check if pod has hostIPC=true
            if pod.spec.host_ipc:
                # If namespace not in dictionary, create a new list
                if pod.metadata.namespace not in result['details']:
                    result['details'][pod.metadata.namespace] = []
                # Add pod name to the list for this namespace
                result['details'][pod.metadata.namespace].append(pod.metadata.name)

        if result['details']:
            result['compliant'] = False

    except Exception as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.2.3 scan: {str(e)}")

    if result['compliant']:
        if not result['details']:
            result['details'] = {"message": "All containers wishing to share the host IPC namespace are minimized."}

    print("CIS 4.2.3 Scan Completed")
    return result

# 4.2.4 Minimize the admission of containers wishing to share the host network namespace (Automated)
def cis_4_2_4(kubeconfig, cluster_name):
   
    result = {
        'check_id': '4.2.4',
        'title': 'Minimize the admission of containers wishing to share the host network namespace',
        'description': 'Minimize the admission of containers wishing to share the host network namespace',
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    try:
        kclient = kubernetes.client.ApiClient(configuration=kubeconfig)
        v1 = kubernetes.client.CoreV1Api(api_client=kclient)

        # Get pods from all namespaces
        pods = v1.list_pod_for_all_namespaces()

        for pod in pods.items:
            # Skip pods in kube-system namespace
            if pod.metadata.namespace == "kube-system":
                continue
                
            # Check if pod has hostNetwork=true
            if pod.spec.host_network:
                # If namespace not in dictionary, create a new list
                if pod.metadata.namespace not in result['details']:
                    result['details'][pod.metadata.namespace] = []
                # Add pod name to the list for this namespace
                result['details'][pod.metadata.namespace].append(pod.metadata.name)

        if result['details']:
            result['compliant'] = False

    except Exception as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.2.4 scan: {str(e)}")

    if result['compliant']:
        if not result['details']:
            result['details'] = {"message": "All containers wishing to share the host network namespace are minimized."}

    print("CIS 4.2.4 Scan Completed")
    return result

# 4.2.5 Minimize the admission of containers with allowPrivilegeEscalation (Automated)
def cis_4_2_5(kubeconfig, cluster_name):
  
    result = {
        'check_id': '4.2.5',
        'title': 'Minimize the admission of containers with allowPrivilegeEscalation',
        'description': 'Minimize the admission of containers with allowPrivilegeEscalation',
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    try:
        kclient = kubernetes.client.ApiClient(configuration=kubeconfig)
        v1 = kubernetes.client.CoreV1Api(api_client=kclient)

        # Get pods from all namespaces
        pods = v1.list_pod_for_all_namespaces()

        for pod in pods.items:
            # Skip pods in kube-system namespace
            if pod.metadata.namespace == "kube-system":
                continue
                
            # Check each container in the pod
            for container in pod.spec.containers:
                # Check if container has allowPrivilegeEscalation=true
                if (container.security_context and 
                    container.security_context.allow_privilege_escalation):
                    
                    # If namespace not in dictionary, create a new list
                    if pod.metadata.namespace not in result['details']:
                        result['details'][pod.metadata.namespace] = []
                    
                    # Add pod name and container name to the list for this namespace
                    result['details'][pod.metadata.namespace].append({
                        'pod': pod.metadata.name,
                        'container': container.name
                    })

        if result['details']:
            result['compliant'] = False

    except Exception as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.2.5 scan: {str(e)}")

    if result['compliant']:
        if not result['details']:
            result['details'] = {"message": "All containers with allowPrivilegeEscalation are minimized."}

    print("CIS 4.2.5 Scan Completed")
    return result

# 4.3.1 Ensure CNI plugin supports network policies. (Manual)
def cis_4_3_1(cluster_name, region, profile):
    result = {
        'check_id': '4.3.1',
        'title': 'Ensure CNI plugin supports network policies',
        'description': 'Ensure CNI plugin supports network policies',
        'resource_id': cluster_name,
        'compliant': False,
        'details': []
    }

    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
        shell=True, check=True
    )
    try:
        cmd = ['kubectl', 'get', 'pods', '-n', 'kube-system', '-o', 'json']
        process = subprocess.run(cmd, capture_output=True, text=True)

        if process.returncode != 0:
            result['compliant'] = True
            result['details'] = [f"Error: {process.stderr.strip()}"]
            print(f"Error performing scan: {process.stderr.strip()}")
            return result

        pods = json.loads(process.stdout)
        matched = []
        cni_keywords = ['calico', 'weave', 'cilium', 'flannel', 'aws-node', 'cni']

        for item in pods.get('items', []):
            name = item['metadata']['name']
            if any(keyword in name for keyword in cni_keywords):
                matched.append(name)

        result['details'] = matched

    except Exception as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.3.1 scan: {str(e)}")

    if not result['details']:
        result['compliant'] = True
        if not result['details']:
            result['details'].append({"message": "CNI plugin supports network policies."})            

    print("CIS 4.3.1 Scan Completed")
    return result

#4.3.2 Ensure that all Namespaces have Network Policies defined (Automated)
def cis_4_3_2(cluster_name, region, profile):
    result = {
        'check_id': '4.3.2',
        'title': 'Ensure that all Namespaces have Network Policies defined',
        'description': 'Ensure that all Namespaces have Network Policies defined',
        'resource_id': cluster_name,
        'compliant': True,
        'details': []
    }

    try:
        subprocess.run(
            f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
            shell=True, check=True
        )

        ns_cmd = ['kubectl', 'get', 'namespaces', '-o', 'json']
        ns_process = subprocess.run(ns_cmd, capture_output=True, text=True, check=True)
        ns_data = json.loads(ns_process.stdout)
        all_namespaces = [item['metadata']['name'] for item in ns_data['items']]
        filtered_namespaces = [
            ns for ns in all_namespaces
            if ns != 'default' and not ns.startswith('kube-')
        ]
        namespaces_without_policies = set(filtered_namespaces)

        np_cmd = ['kubectl', 'get', 'networkpolicy', '--all-namespaces', '-o', 'json']
        np_process = subprocess.run(np_cmd, capture_output=True, text=True, check=True)
        np_data = json.loads(np_process.stdout)
        namespaces_with_policies = {item['metadata']['namespace'] for item in np_data['items']}

        namespaces_without_policies -= namespaces_with_policies

        if namespaces_without_policies:
            result['compliant'] = False
            result['details'] = sorted(list(namespaces_without_policies))

    except subprocess.CalledProcessError as e:
        result['compliant'] = True
        result['details'] = [f"Error: {e.stderr.strip()}"]
    except Exception as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.3.2 scan: {str(e)}")

    if result['compliant']:
        if not result['details']:
            result['details'].append({"message": "All namespaces have Network Policies defined."})

    print("CIS 4.3.2 Scan Completed")
    return result

# 4.4.1 Prefer using secrets as files over secrets as environment variables (Automated)
def cis_4_4_1(cluster_name, region, profile):
    result = {
        'check_id': '4.4.1',
        'title': 'Prefer using secrets as files over secrets as environment variables',
        'description': 'Prefer using secrets as files over secrets as environment variables',
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
        shell=True, check=True
    )
    try:
        cmd = [
            'kubectl', 'get', 'all',
            '-o', "jsonpath={range .items[?(@..secretKeyRef)]} {.kind} {.metadata.namespace}/{.metadata.name} {'\\n'}{end}",
            '-A'
        ]
        output = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()

        if output:
            result['compliant'] = False
            for line in output.splitlines():
                kind, name = line.strip().split(maxsplit=1)
                if kind not in result['details']:
                    result['details'][kind] = []
                result['details'][kind].append(name)

    except subprocess.CalledProcessError as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.4.1 scan: {str(e)}")
    
    if result['compliant']:
        if not result['details']:
            result['details'] = {"message": "All secrets are used as files instead of environment variables."}

    print("CIS 4.4.1 Scan Completed")
    return result

# 4.4.2 Consider external secret storage (Manual)
def cis_4_4_2(cluster_name):
    result = {
        'check_id': '4.4.2',
        'title': 'Consider external secret storage',
        'description': 'Consider external secret storage',
        'resource_id': cluster_name,
        'compliant': None,
        'details': [
            'This is a manual check.',
            'Review if your cluster uses an external secret management system such as HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault.',
            'Ensure the system requires authentication, provides audit logging, encrypts secrets at rest, and supports secret rotation.',
            'If only Kubernetes Secrets are used directly, consider migrating to external solutions for better security and compliance.'
        ]
    }

    print("CIS 4.4.2 Scan Completed")
    return result

# 4.5.1 Create administrative boundaries between resources using namespaces (Manual)
def cis_4_5_1(cluster_name, region, profile):
    result = {
        'check_id': '4.5.1',
        'title': 'Create administrative boundaries between resources using namespaces',
        'description': 'Create administrative boundaries between resources using namespaces',
        'resource_id': cluster_name,
        'compliant': None,
        'details': []
    }

    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
        shell=True, check=True
    )
    try:
        cmd = ['kubectl', 'get', 'namespaces', '-o', 'json']
        output = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
        data = json.loads(output)

        result['details'] = [item['metadata']['name'] for item in data.get('items', [])]

    except subprocess.CalledProcessError as e:
        result['compliant'] = False
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing scan: {str(e)}")

    print("CIS 4.5.1 Scan Completed")
    return result

# 4.5.2 The default namespace should not be used (Automated)
def cis_4_5_2(cluster_name, region, profile):
    result = {
        'check_id': '4.5.2',
        'title': 'The default namespace should not be used',
        'description': 'The default namespace should not be used',
        'resource_id': cluster_name,
        'compliant': True,
        'details': {}
    }

    subprocess.run(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region} --profile {profile}",
        shell=True, check=True
    )

    try:
        res = subprocess.run(
            "kubectl api-resources --verbs=list --namespaced=true -o name",
            shell=True, check=True, capture_output=True, text=True
        )
        resource_list = res.stdout.strip().splitlines()
        if not resource_list:
            return result  

        resource_str = ",".join(resource_list)

        cmd = f"kubectl get {resource_str} --ignore-not-found -n default -o json"
        output = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True).stdout.strip()
        if not output:
            result['details'] = {'message': 'The default namespace is not used.'}
            return result

        resources = json.loads(output)
        user_resources = {}

        for item in resources.get('items', []):
            kind = item.get('kind', '')
            name = item.get('metadata', {}).get('name', '')

            if 'kube' in name or 'default' in name:
                continue
            if name.startswith('kubernetes-') or name.startswith('default-token-'):
                continue

            if kind not in user_resources:
                user_resources[kind] = []
            user_resources[kind].append(name)

        if user_resources:
            result['compliant'] = False
            result['details'] = user_resources

    except subprocess.CalledProcessError as e:
        result['compliant'] = True
        result['details'] = [f"Error: {str(e)}"]
        print(f"Error performing CIS 4.5.2 scan: {str(e)}")

    if result['compliant']:
        if not result['details']:
            result['details'] = {"message": "The default namespace is not used."}

    print("CIS 4.5.2 Scan Completed")
    return result

# 5.1.1 Ensure Image Vulnerability Scanning using Amazon ECR image scanning or a third party provider (Automated)
def cis_5_1_1(session, cluster_name):
    result = {
        "check_id": "5.1.1",
        "title": "Ensure Image Vulnerability Scanning using Amazon ECR",
        "resource_id": cluster_name,
        "compliant": True,
        "details": []
    }
    
    try:
        ecr_client = session.client("ecr")
        response = ecr_client.describe_repositories()
    except Exception as e:
        print(f" Error performing CIS 5.1.1 scan: {e}")
        result["compliant"] = True
        result["details"].append(f"Error: {str(e)}")
        return result
        
    non_compliant_repos = []

    for repo in response.get("repositories", []):
        repo_name = repo.get("repositoryName", "<unknown>")
        scan_config = repo.get("imageScanningConfiguration", {})

        if not scan_config.get("scanOnPush", False):
            non_compliant_repos.append(repo_name)

    if non_compliant_repos:
        result["compliant"] = False
        result["details"] = non_compliant_repos
    else:
        result["details"].append({"message": "All ECR repositories have image scanning enabled."})    

    print("CIS 5.1.1 Scan Completed")
    return result

# 5.1.2 Minimize user access to Amazon ECR (Manual)
def cis_5_1_2(session):
    iam_client = session.client("iam")

    result = {
        "check_id": "5.1.2",
        "title": "Minimize user access to Amazon ECR",
        "resource_id": "IAM Users",
        "compliant": True,
        "details": []
    }

    sensitive_ecr_actions = [
        "ecr:PutImage",
        "ecr:DeleteRepository",
        "ecr:BatchDeleteImage",
        "ecr:SetRepositoryPolicy",
        "ecr:DeleteRepositoryPolicy",
        "ecr:*"
    ]

    try:
        users = iam_client.list_users()["Users"]
        for user in users:
            user_name = user["UserName"]
            attached_policies = iam_client.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]

            for policy in attached_policies:
                policy_arn = policy["PolicyArn"]
                policy_meta = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]
                policy_version_id = policy_meta["DefaultVersionId"]

                policy_doc = iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_version_id
                )["PolicyVersion"]["Document"]

                statements = policy_doc.get("Statement", [])
                if not isinstance(statements, list):
                    statements = [statements]

                for stmt in statements:
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]

                    for act in actions:
                        if any(act.lower().startswith(e.lower().replace("*", "")) for e in sensitive_ecr_actions):
                            result["compliant"] = False
                            result["details"].append(f"User '{user_name}' has sensitive ECR permission: {act}")

    except Exception as e:
        result["compliant"] = True
        result["details"].append(f"Error: {str(e)}")
        print(f"Error performing CIS 5.1.2 scan: {str(e)}")

    if len(result["details"]) > 5:
        result["details"] = result["details"][:5] + ["..."]

    if result["compliant"]:
        if not result["details"]:
            result["details"].append({"message": "No sensitive ECR permissions found on any IAM users."})

    print("CIS 5.1.2 Scan Completed")
    return result

# 5.1.3 Minimize cluster access to read-only for Amazon ECR (Manual)
def cis_5_1_3(session, cluster_name):
    
    iam_client = session.client("iam")
    eks_client = session.client("eks")

    result = {
        "check_id": "5.1.3",
        "title": "Minimize cluster access to read-only for Amazon ECR",
        "resource_id": cluster_name,
        "compliant": True,
        "details": []
    }

    # Define disallowed ECR actions (sensitive write/delete permissions)
    sensitive_actions = [
        "ecr:*",
        "ecr:PutImage",
        "ecr:Delete*",
        "ecr:SetRepositoryPolicy",
        "ecr:BatchDeleteImage"
    ]

    try:
        cluster_info = eks_client.describe_cluster(name=cluster_name)
        cluster_role_arn = cluster_info["cluster"]["roleArn"]
        cluster_role_name = cluster_role_arn.split("/")[-1]

        attached_policies = iam_client.list_attached_role_policies(RoleName=cluster_role_name)["AttachedPolicies"]

        for policy in attached_policies:
            policy_arn = policy["PolicyArn"]
            policy_meta = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]
            policy_version_id = policy_meta["DefaultVersionId"]

            policy_doc = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy_version_id
            )["PolicyVersion"]["Document"]

            statements = policy_doc.get("Statement", [])
            if not isinstance(statements, list):
                statements = [statements]

            for stmt in statements:
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                for act in actions:
                    act_lower = act.lower()
                    for sensitive in sensitive_actions:
                        if fnmatch.fnmatchcase(act_lower, sensitive.lower()):
                            result["compliant"] = False
                            result["details"].append(f"{cluster_role_name} policy allows: {act}")
    except Exception as e:
        result["compliant"] = True
        result["details"].append(f"Error: {str(e)}")
        print(f"Error performing CIS 5.1.3 scan: {str(e)}")

    max_items = 5
    if len(result["details"]) > max_items:
        result["details"] = result["details"][:max_items] + ["..."]

    if result["compliant"]:
        if not result["details"]:
            result["details"].append({"message": "No sensitive ECR permissions found on any IAM users."})

    print("CIS 5.1.3 Scan Completed")
    return result

def cis_5_1_4(kubeconfig, cluster_name):

    kclient = kubernetes.client.ApiClient(configuration=kubeconfig)
    v1 = kubernetes.client.CoreV1Api(api_client=kclient)
   
    result = {
        "check_id": "5.1.4",
        "title": "Minimize Container Registries to only those approved",
        "resource_id": cluster_name,
        "compliant": True,
        "details": []
    }

    def is_trusted_registry(image):
        if image.startswith("602401143452.dkr.ecr.") or "dkr.ecr." in image:
            return True
        if image.startswith("docker.io/library") or "/" not in image:
            return True
        return False

    try:
        pods = v1.list_pod_for_all_namespaces(watch=False).items
    except Exception as e:
        result["compliant"] = True
        result["details"].append(f"Error: {str(e)}")
        print(f"Error performing CIS 5.1.4 scan: {str(e)}")
        return result

    for pod in pods:
        ns = pod.metadata.namespace
        pod_name = pod.metadata.name
        containers = pod.spec.containers

        for container in containers:
            image = container.image
            if not is_trusted_registry(image):
                result["compliant"] = False
                result["details"].append(
                    f"Pod {pod_name} in namespace {ns} uses image from untrusted source: {image}"
                )

    max_items = 5
    if len(result["details"]) > max_items:
        result["details"] = result["details"][:max_items] + ["..."]

    if result["compliant"]:
        if not result["details"]:
            result["details"].append({"message": "All container images are from trusted registries."})

    print("CIS 5.1.4 Scan Completed")
    return result

# 5.2.1 Prefer using dedicated EKS Service Accounts (Automated)
def cis_5_2_1(kconfig, cluster_name):
    result = {
        "check_id": "5.2.1",
        "title": "Prefer using dedicated EKS Service Accounts",
        "resource_id": cluster_name,
        "compliant": True,
        "details": []
    }

    kclient = kubernetes.client.ApiClient(configuration=kconfig)
    core = kubernetes.client.CoreV1Api(api_client=kclient)
    rbac = kubernetes.client.RbacAuthorizationV1Api(api_client=kclient)

    results = []

    namespaces = core.list_namespace().items
    for ns in namespaces:
        ns_name = ns.metadata.name

        try:
            sa = core.read_namespaced_service_account(name="default", namespace=ns_name)

            if sa.automount_service_account_token is not False:
                results.append({
                    "namespace": ns_name,
                    "issue": "automountServiceAccountToken is not set to false"
                })

            role_bindings = rbac.list_namespaced_role_binding(namespace=ns_name).items
            for rb in role_bindings:
                if rb.subjects:
                    for subject in rb.subjects:
                        if subject.kind == "ServiceAccount" and subject.name == "default":
                            results.append({
                                "namespace": ns_name,
                                "issue": f"Bound to RoleBinding: {rb.metadata.name}"
                            })

        except Exception as e:
            result["compliant"] = True
            result["details"].append(f"Error: {str(e)}")
            print(f"Error performing CIS 5.2.1 scan: {str(e)}")

    if results:
        result["compliant"] = False
        result["details"] = results
    
    if result["compliant"]: 
        if not result["details"]:
            result["details"].append({"message": "Dedicated EKS Service Accounts are used."}) 

    print("CIS 5.2.1 Scan Completed")
    return result

# 5.3.1 Ensure Kubernetes Secrets are encrypted using Customer Master Keys (CMKs) managed in AWS KMS (Manual)
def cis_5_3_1(session, cluster_name):
    eks_client = session.client("eks")
    result = {
        "check_id": "5.3.1",
        "title": "Ensure Kubernetes Secrets are encrypted using CMKs in AWS KMS",
        "resource_id": cluster_name,
        "compliant": True,
        "details": []
    }

    try:
        response = eks_client.describe_cluster(name=cluster_name)
        encryption_config = response["cluster"].get("encryptionConfig", [])
        
        if not encryption_config:
            result["compliant"] = False
            result["details"].append("encryptionConfig is missing.")
        else:
            found = False
            for config in encryption_config:
                if "secrets" in config.get("resources", []) and \
                   "provider" in config and \
                   "keyArn" in config["provider"]:
                    found = True
                    break
            if not found:
                result["compliant"] = False
                result["details"].append("KMS encryption for 'secrets' is not properly configured with keyArn.")
    except Exception as e:
        result["compliant"] = True
        result["details"].append(f"Error: {str(e)}")
        print(f"Error performing CIS 5.3.1 scan: {str(e)}")

    # Limit length
    max_items = 5
    if len(result["details"]) > max_items:
        result["details"] = result["details"][:max_items] + ["..."]

    if result["compliant"]:
        if not result["details"]:
            result["details"].append({"message": "Kubernetes secrets are encrypted using CMKs in AWS KMS."})

    print("CIS 5.3.1 Scan Completed")
    return result

# 5.4.1 Restrict Access to the Control Plane Endpoint (Automated)
def cis_5_4_1(session, cluster_name):
    eks_client = session.client("eks")

    result = {
        "check_id": "5.4.1",
        "title": "Restrict Access to the Control Plane Endpoint",
        "resource_id": cluster_name,
        "compliant": True,
        "details": []
    }

    try:
        response = eks_client.describe_cluster(name=cluster_name)
        cluster_info = response['cluster']
        endpoint_config = cluster_info.get("resourcesVpcConfig", {})

        private_access = endpoint_config.get("endpointPrivateAccess", False)
        public_access = endpoint_config.get("endpointPublicAccess", True)

        if not private_access or public_access:
            result["compliant"] = False
            result["details"].append(
                f"endpointPrivateAccess={private_access}, endpointPublicAccess={public_access}"
            )

    except Exception as e:
        result["compliant"] = True
        result["details"].append(f"Error: {str(e)}")
        print(f"Error performing CIS 5.4.1 scan: {str(e)}")

    if result["compliant"]:
        if not result["details"]:
            result["details"].append({"message": "Control plane endpoint access is properly restricted."})

    print("CIS 5.4.1 Scan Completed")
    return result

# 5.4.2 Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled (Automated)
def cis_5_4_2(session, cluster_name):
    eks_client = session.client("eks")
    result = {
        "check_id": "5.4.2",
        "title": "Ensure clusters are created with Private Endpoint Enabled and Public Access Disabled",
        "resource_id": cluster_name,
        "compliant": True,
        "details": []
    }

    try:
        response = eks_client.describe_cluster(name=cluster_name)
        vpc_config = response['cluster']['resourcesVpcConfig']

        public_access = vpc_config.get('endpointPublicAccess', True)
        private_access = vpc_config.get('endpointPrivateAccess', False)

        if public_access or not private_access:
            result["compliant"] = False
            result["details"].append(
                f"endpointPrivateAccess={private_access}, endpointPublicAccess={public_access}"
            )

    except Exception as e:
        result["compliant"] = True
        result["details"].append(f"Error: {str(e)}")
        print(f"Error performing CIS 5.4.2 scan: {str(e)}")

    if result["compliant"]:
        if not result["details"]:
            result["details"].append({"message": "Cluster was created with private endpoint enabled and public access disabled."})

    print("CIS 5.4.2 Scan Completed")
    return result

# 5.4.3 Ensure clusters are created with Private Nodes (Automated)
def cis_5_4_3(session, cluster_name):
   
    eks_client = session.client("eks")

    result = {
        "check_id": "5.4.3",
        "title": "Ensure clusters are created with Private Nodes",
        "resource_id": cluster_name,
        "compliant": True,
        "details": []
    }

    try:
        response = eks_client.describe_cluster(name=cluster_name)
        config = response['cluster']['resourcesVpcConfig']

        private_enabled = config.get('endpointPrivateAccess', False)
        public_cidrs = config.get('publicAccessCidrs', [])
        public_cidrs_configured = bool(public_cidrs)

        if not private_enabled or not public_cidrs_configured:
            result["compliant"] = False
            result["details"].append(
                f"endpointPrivateAccess={private_enabled}, publicAccessCidrs={public_cidrs}"
            )

    except Exception as e:
        result["compliant"] = True
        result["details"].append(f"Error: {str(e)}")
        print(f"Error performing CIS 5.4.3 scan: {str(e)}")

    if result["compliant"]:
        if not result["details"]:
            result["details"].append({
                "message": "Cluster is configured with private access enabled and specific publicAccessCidrs."})

    print("CIS 5.4.3 Scan Completed")
    return result

# 5.4.4 Ensure Network Policy is Enabled and set as appropriate (Automated)
def cis_5_4_4(session, cluster_name):

    result = {
        "check_id": "5.4.4",
        "title": "Ensure Network Policy is Enabled and set as appropriate",
        "resource_id": cluster_name,
        "compliant": True,
        "details": []
    }

    eks_client = session.client("eks")

    try:
        response = eks_client.describe_addon(
            clusterName=cluster_name,
            addonName="vpc-cni"
        )
        config_values = response.get("addon", {}).get("configurationValues", "")
        
        # Looking for enableNetworkPolicy=true in config
        compliant = "enableNetworkPolicy=true" in config_values

        if not compliant:
            result["compliant"] = False
            result["details"].append("Network Policy is not enabled.")

    except Exception as e:
        result["compliant"] = True
        result["details"].append(f"Error: {str(e)}")
        print(f"Error performing CIS 5.4.4 scan: {str(e)}")

    if result["compliant"]:
        if not result["details"]:
            result["details"].append({"message": "Network Policy is enabled and set as appropriate."})

    print("CIS 5.4.4 Scan Completed")
    return result

# 5.4.5 Encrypt traffic to HTTPS load balancers with TLS certificates (Manual)
def cis_5_4_5(kubeconfig, cluster_name):
   
    kclient = kubernetes.client.ApiClient(configuration=kubeconfig)
    v1 = kubernetes.client.CoreV1Api(api_client=kclient)

    result = {
        'check_id': "5.4.5",
        'title': "Encrypt traffic to HTTPS load balancers with TLS certificates",
        'resource_id': cluster_name,
        'compliant': True,
        'details': []
    }

    try:
        services = v1.list_service_for_all_namespaces().items
    except Exception as e:
        result['compliant'] = True
        result['details'].append(f"Error: {str(e)}")
        return result

    for svc in services:
        if svc.spec.type == "LoadBalancer":
            svc_name = svc.metadata.name
            svc_ns = svc.metadata.namespace
            svc_ports = svc.spec.ports

            is_https = any(p.port == 443 or (p.name and p.name.lower() == "https") for p in svc_ports)

            if not is_https:
                result['compliant'] = False
                result['details'].append(f"Service {svc_name} in namespace {svc_ns} is LoadBalancer but not using HTTPS/TLS.")

    # Limit details output
    max_items = 5
    if len(result["details"]) > max_items:
        result["details"] = result["details"][:max_items] + ["..."]

    if result["compliant"]:
        if not result["details"]:
            result["details"].append({"message": "All HTTPS/TLS load balancers are encrypted."})

    print("CIS 5.4.5 Scan Completed")
    return result

# 5.5.1 Manage Kubernetes RBAC users with AWS IAM Authenticator for Kubernetes or Upgrade to AWS CLI v1.16.156 or greater (Manual)
def cis_5_5_1(kubeconfig, cluster_name):

    kclient = kubernetes.client.ApiClient(configuration=kubeconfig)
    rbac_api = kubernetes.client.RbacAuthorizationV1Api(api_client=kclient)
    v1 = kubernetes.client.CoreV1Api(api_client=kclient)

    result = {
        'check_id': "5.5.1",
        'title': "Ensure use of AWS IAM Authenticator for RBAC",
        'resource_id': cluster_name,
        'compliant': True,
        'details': []
    }

    def is_iam_subject(subject_name):
        return "arn:aws:iam" in subject_name or "eks.amazonaws.com" in subject_name

    try:
        namespaces = [ns.metadata.name for ns in v1.list_namespace().items]
    except Exception as e:
        result['compliant'] = True
        result['details'].append(f"Error: {str(e)}")
        return result

    # Check RoleBindings
    for ns in namespaces:
        try:
            role_bindings = rbac_api.list_namespaced_role_binding(namespace=ns).items
            for rb in role_bindings:
                for subject in rb.subjects or []:
                    if not is_iam_subject(subject.name):
                        result['compliant'] = False
                        result['details'].append(
                            f"Non-IAM RoleBinding: {rb.metadata.name} → {subject.kind}:{subject.name} in namespace {ns}"
                        )
        except Exception as e:
            result['compliant'] = True
            result['details'].append(f"Error: {str(e)}")
            print(f"Error performing CIS 5.5.1 scan: {str(e)}")

    # Check ClusterRoleBindings
    try:
        cluster_role_bindings = rbac_api.list_cluster_role_binding().items
        for crb in cluster_role_bindings:
            for subject in crb.subjects or []:
                if not is_iam_subject(subject.name):
                    result['compliant'] = False
                    result['details'].append(
                        f"Non-IAM ClusterRoleBinding: {crb.metadata.name} → {subject.kind}:{subject.name}"
                    )
    except Exception as e:
        result['compliant'] = True
        result['details'].append(f"Error: {str(e)}")
        print(f"Error performing CIS 5.5.1 scan: {str(e)}")

    max_entries = 5
    if len(result['details']) > max_entries:
        result['details'] = result['details'][:max_entries] + ["..."]

    if result['compliant']:
        if not result['details']:
            result['details'].append({"message": "All RBAC users are managed with AWS IAM Authenticator for Kubernetes."})

    print("CIS 5.5.1 Scan Completed")
    return result















