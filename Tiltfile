load('ext://restart_process', 'docker_build_with_restart')
load('ext://helm_resource', 'helm_resource', 'helm_repo')

# Consul
helm_repo('hashicorp', 'https://helm.releases.hashicorp.com')
helm_resource(
    'consul',
    'hashicorp/consul',
    namespace='consul',
    flags=[
        '--namespace=consul',
        '--create-namespace',
        '--set=global.name=consul',
        '--values=./infra/helm/values/dev/_consul-values.yaml',
    ],
    pod_readiness='ignore',
    resource_deps=['hashicorp'],
    labels='tooling',
)
k8s_resource(
    'consul',
    port_forwards=['8501:8500'],
    labels='tooling',
    extra_pod_selectors=[{'component': 'server'}],
    discovery_strategy='selectors-only',
)
