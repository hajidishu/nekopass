package protocol

// CurrentVersion is the configuration capability version advertised by the agent.
const CurrentVersion int32 = 35

// EncryptedTunnelVersion adds durable handshake replay protection, the DTLS
// metadata envelope, and continuous Mux padding. Both endpoints must support it.
const EncryptedTunnelVersion int32 = 35

const MuxVersion int32 = 34

const ClientTCPBrutalVersion int32 = 33

const BrutalVersion int32 = 32

const DDNSInterfaceVersion int32 = 30
