package resource

// SSHKeys are a node's SSH identities. Every field is a *public* key.
//
// Nothing secret travels here and nothing secret is stored on the hub. A
// private key never leaves the machine that generated it; what the hub holds is
// the same class of thing it already holds for WireGuard — an identifier that
// is useless to whoever steals it and meaningless to keep hidden.
//
// The two halves solve two different prompts, and a mesh that fixes only one
// still makes people type things:
//
//   - User is the key an operator logs in *with*. Its public half belongs in
//     peers' authorized_keys, and installing it is what stops the password
//     prompt. Because it grants access, distribution is opt-in.
//
//   - Host keys identify the machine being logged in *to*. They belong in
//     peers' known_hosts, and they are what stops "The authenticity of host
//     '10.99.0.4' can't be established". A host key grants nothing — publishing
//     it only lets others recognise this machine — so it is distributed by
//     default. Doing so is strictly better than the alternative everyone
//     actually uses, which is to type "yes" without reading the fingerprint.
type SSHKeys struct {
	// User is a single-line OpenSSH public key, or empty when this machine
	// has no operator key to offer.
	User string `json:"user,omitempty"`
	// Host are this machine's SSH host public keys, one line each, in the
	// format known_hosts expects after the hostname field.
	Host []string `json:"host,omitempty"`
}

// Empty reports whether there is nothing to publish.
func (k SSHKeys) Empty() bool { return k.User == "" && len(k.Host) == 0 }
