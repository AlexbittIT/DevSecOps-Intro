# Two extra checks the shipped k8s-security.rego does not make.
# Same package as the shipped policy, so conftest evaluates them together.
package k8s.security

# DENY: every container image must be pinned by digest (@sha256:...),
# not by a mutable tag. The shipped policy only forbids ":latest".
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q image must be pinned by digest (@sha256:...), not a tag", [c.name])
}

# WARN: the pod explicitly turns ServiceAccount-token auto-mount ON. A workload
# that does not call the Kubernetes API should not carry a token. The shipped
# policy never checks this. (Passes when the field is absent, as in the hardened
# manifest; fires only when it is set to true.)
warn contains msg if {
  input.kind == "Deployment"
  input.spec.template.spec.automountServiceAccountToken == true
  some c in input.spec.template.spec.containers
  msg := sprintf("pod of container %q should not set automountServiceAccountToken: true", [c.name])
}
