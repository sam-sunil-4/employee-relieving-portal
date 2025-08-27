# employee-relieving-portal
centralised dashboard for employee relieving access check.


This is a tool built using Python-Flask along with HTML, CSS, JS, and Jinja. This tool is designed in such a way that you can check the access of the users in AWS, Azure, and Gitlab using their email ID. (Please note the username needs to be email ID of the user in order to get this working.)


Attached the manifests files to deploy them into the Kubernetes cluster and expose them via a load balancer. Also, the env variables are stored in AWS SSM parameter store, and these secrets where fetched to the cluster using external secrets operator (ESO). The ESO will fetch the env from parameter store and keep them as external secrets in the cluster.

Also we are using a reloader to autoamtically restart the pod to take this env change into effect. You can install the reloader using Helm by following the commands below

helm repo add stakater https://stakater.github.io/stakater-charts

helm repo update

helm install reloader stakater/reloader
