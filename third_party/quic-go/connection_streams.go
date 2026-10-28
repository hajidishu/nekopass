package quic

// OutgoingBidirectionalStreams returns the number of locally initiated
// bidirectional streams that have not completed both directions. Reliable send
// data and FINs keep a stream in this set until acknowledged. Unidirectional
// control streams and unreliable DATAGRAMs are not counted. A closed connection
// can retain entries; callers must also check Conn.Context().
func (c *Conn) OutgoingBidirectionalStreams() int {
	m := c.streamsMap
	m.mutex.Lock()
	defer m.mutex.Unlock()
	streams := m.outgoingBidiStreams
	streams.mutex.RLock()
	defer streams.mutex.RUnlock()
	return len(streams.streams)
}
