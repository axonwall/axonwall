# ==============================================================================
# Oh My Zsh — kubectl plugin (https://github.com/ohmyzsh/ohmyzsh/tree/master/plugins/kubectl)
# Kubernetes (K3s + OpenEBS) autocompletion, context switching & operator aliases
# ==============================================================================

# Auto-detect K3s kubeconfig on Axonwall appliances if KUBECONFIG is not explicitly set
if [[ -z "${KUBECONFIG:-}" ]] && [[ -r /etc/rancher/k3s/k3s.yaml ]]; then
  export KUBECONFIG="/etc/rancher/k3s/k3s.yaml"
fi

# If k3s is installed without standalone kubectl symlink, provide seamless wrapper
if ! (( $+commands[kubectl] )) && (( $+commands[k3s] )); then
  function kubectl() {
    command k3s kubectl "$@"
  }
fi

# Generate and cache official kubectl zsh completion when kubectl is present
if (( $+commands[kubectl] )) || (( $+commands[k3s] )); then
  if [[ ! -f "${ZSH_CACHE_DIR}/completions/_kubectl" ]]; then
    kubectl completion zsh 2>/dev/null >| "${ZSH_CACHE_DIR}/completions/_kubectl" &|
  fi
  [[ -s "${ZSH_CACHE_DIR}/completions/_kubectl" ]] && source "${ZSH_CACHE_DIR}/completions/_kubectl" 2>/dev/null
fi

# Built-in fallback completion for kubectl / k so completion works even before K3s starts
_axonwall_kubectl_fallback() {
  local -a subcmds resources
  subcmds=(
    'get:Display one or many Kubernetes resources'
    'describe:Show details of a specific resource or group of resources'
    'logs:Print the logs for a container in a pod'
    'exec:Execute a command in a container'
    'apply:Apply a configuration to a resource by file name or stdin'
    'delete:Delete resources by file names, stdin, resources and names, or label selector'
    'create:Create a resource from a file or from stdin'
    'edit:Edit a resource on the server'
    'rollout:Manage the rollout of a resource'
    'scale:Set a new size for a deployment, replica set, or replication controller'
    'port-forward:Forward one or more local ports to a pod'
    'top:Display resource (CPU/memory) usage of nodes or pods'
    'cordon:Mark node as unschedulable'
    'uncordon:Mark node as schedulable'
    'drain:Drain node in preparation for maintenance'
    'taint:Update the taints on one or more nodes'
    'label:Update the labels on a resource'
    'annotate:Update the annotations on a resource'
    'config:Modify kubeconfig files (use-context, get-contexts, set-context)'
    'cluster-info:Display cluster endpoint info'
    'explain:Get documentation for a resource'
    ' events:List cluster events'
    'version:Print the client and server version information'
  )
  resources=(
    'pods' 'po' 'deployments' 'deploy' 'services' 'svc' 'nodes' 'no'
    'namespaces' 'ns' 'ingresses' 'ing' 'configmaps' 'cm' 'secrets' 'sec'
    'persistentvolumeclaims' 'pvc' 'persistentvolumes' 'pv' 'storageclasses' 'sc'
    'statefulsets' 'sts' 'daemonsets' 'ds' 'jobs' 'cronjobs' 'cj'
    'replicasets' 'rs' 'endpoints' 'ep' 'serviceaccounts' 'sa' 'events' 'ev'
    'networkpolicies' 'netpol' 'zfsvolumes' 'zv'
  )
  if (( CURRENT == 2 )); then
    _describe 'kubectl command' subcmds
  elif (( CURRENT == 3 )); then
    case "${words[2]}" in
      get|describe|delete|edit|explain|top|rollout|scale)
        _describe 'kubernetes resource' resources
        ;;
      *)
        _files
        ;;
    esac
  else
    _files
  fi
}

if ! (( $+functions[__start_kubectl] )); then
  compdef _axonwall_kubectl_fallback kubectl k 2>/dev/null || true
else
  compdef __start_kubectl k 2>/dev/null || true
fi

# Core command alias
alias k='kubectl'

# Execute a kubectl command against all namespaces
alias kall='kubectl --all-namespaces'
alias kca='_kca(){ kubectl "$@" --all-namespaces;  unset -f _kca; }; _kca'

# Apply / Create / Delete
alias kaf='kubectl apply -f'
alias keti='kubectl exec -t -i'
alias kex='kubectl exec -it'
alias kdel='kubectl delete'
alias kdelf='kubectl delete -f'

# Context & Namespace Switching
alias kcuc='kubectl config use-context'
alias kcsc='kubectl config set-context'
alias kcdc='kubectl config delete-context'
alias kccc='kubectl config current-context'
alias kcgc='kubectl config get-contexts'
alias kctx='kubectl config get-contexts'
alias kcn='kubectl config set-context --current --namespace'
alias kns='kubectl config set-context --current --namespace'

# Pod management
alias kgp='kubectl get pods'
alias kgpa='kubectl get pods --all-namespaces'
alias kgpw='kgp --watch'
alias kgpwide='kgp -o wide'
alias kep='kubectl edit pods'
alias kdp='kubectl describe pods'
alias kdelp='kubectl delete pods'
alias kgpall='kubectl get pods --all-namespaces -o wide'

# Service management
alias kgs='kubectl get svc'
alias kgsa='kubectl get svc --all-namespaces'
alias kgsw='kgs --watch'
alias kgswide='kgs -o wide'
alias kes='kubectl edit svc'
alias kds='kubectl describe svc'
alias kdels='kubectl delete svc'

# Ingress management
alias kgi='kubectl get ingress'
alias kgia='kubectl get ingress --all-namespaces'
alias kei='kubectl edit ingress'
alias kdi='kubectl describe ingress'
alias kdeli='kubectl delete ingress'

# Namespace management
alias kgns='kubectl get namespaces'
alias kens='kubectl edit namespace'
alias kdns='kubectl describe namespace'
alias kdelns='kubectl delete namespace'

# ConfigMap & Secret management
alias kgcm='kubectl get configmaps'
alias kgcma='kubectl get configmaps --all-namespaces'
alias kecm='kubectl edit configmap'
alias kdcm='kubectl describe configmap'
alias kdelcm='kubectl delete configmap'
alias kgsec='kubectl get secrets'
alias kgseca='kubectl get secrets --all-namespaces'
alias kdsec='kubectl describe secret'
alias kdelsec='kubectl delete secret'

# Deployment & Rollout management
alias kgd='kubectl get deployment'
alias kgda='kubectl get deployment --all-namespaces'
alias kgdw='kgd --watch'
alias kgdwide='kgd -o wide'
alias ked='kubectl edit deployment'
alias kdd='kubectl describe deployment'
alias kdeld='kubectl delete deployment'
alias ksd='kubectl scale deployment'
alias krsd='kubectl rollout status deployment'
alias kroll='kubectl rollout restart deployment'

function kres(){
  kubectl set env $@ REFRESHED_AT=$(date +%Y%m%d%H%M%S)
}

# StatefulSet & DaemonSet management
alias kgss='kubectl get statefulset'
alias kgssa='kubectl get statefulset --all-namespaces'
alias kess='kubectl edit statefulset'
alias kdss='kubectl describe statefulset'
alias kdelss='kubectl delete statefulset'
alias kgds='kubectl get daemonset'
alias kgdsa='kubectl get daemonset --all-namespaces'
alias keds='kubectl edit daemonset'
alias kdds='kubectl describe daemonset'

# Port forwarding
alias kpf='kubectl port-forward'

# Tools for accessing all information
alias kga='kubectl get all'
alias kgaa='kubectl get all --all-namespaces'

# Logs
alias kl='kubectl logs'
alias kl1h='kubectl logs --since 1h'
alias kl1m='kubectl logs --since 1m'
alias kl1s='kubectl logs --since 1s'
alias klf='kubectl logs -f'
alias klf1h='kubectl logs --since 1h -f'
alias klf1m='kubectl logs --since 1m -f'
alias klf1s='kubectl logs --since 1s -f'

# Node & Cluster management
alias kgno='kubectl get nodes'
alias kgn='kubectl get nodes -o wide'
alias keno='kubectl edit node'
alias kdno='kubectl describe node'
alias kdelno='kubectl delete node'
alias ktopn='kubectl top nodes'
alias ktopp='kubectl top pods --all-namespaces'

# PVC / PV / OpenEBS ZFS storage management
alias kgpvc='kubectl get pvc'
alias kgpvca='kubectl get pvc --all-namespaces'
alias kgpvcw='kgpvc --watch'
alias kepvc='kubectl edit pvc'
alias kdpvc='kubectl describe pvc'
alias kdelpvc='kubectl delete pvc'
alias kgpv='kubectl get pv'
alias kgsc='kubectl get storageclass'
alias kgev='kubectl get events --sort-by=.lastTimestamp'
alias kgeva='kubectl get events --all-namespaces --sort-by=.lastTimestamp'
