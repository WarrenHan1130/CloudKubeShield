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

    return result