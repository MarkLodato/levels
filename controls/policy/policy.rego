package policy

default allow = false

allow {
  attestation := input.attestations[_]
  verified := verify_signature(attestation)
  artifact_name := verify_subject(verified.payload, input.artifact)
  verify_policy(input.policy.allowed, verified.signer, artifact_name, verified.payload.predicateType, verified.payload.predicate)
}

verify_signature(attestation) = verified {
  # FIXME verify the signature through a custom built-in function
  attestation.payloadType == "application/vnd.in-toto+json"
  payload := json.unmarshal(base64.decode(attestation.payload))
  payload._type == "https://in-toto.io/Statement/v0.1"
  verified := {
    "signer": "dummy-signer",
    "payload": payload
  }
}

verify_subject(payload, artifact) = artifact_name {
  some alg
  sub := payload.subject[_]
  sub.digest[alg] == artifact[alg]
  artifact_name := sub.name
}

verify_policy(allowed, signer, artifact_name, predicateType, predicate) {
  predicateType ==  "https://in-toto.io/Provenance/v0.1"
  signer == allowed.signer
  predicate.builder.id == allowed.builder
  predicate.materials[predicate.recipe.definedInMaterial].uri == allowed.source
}
