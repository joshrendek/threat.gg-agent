package telnet

import "io"

const (
	IAC  byte = 0xFF
	WILL byte = 0xFB
	WONT byte = 0xFC
	DO   byte = 0xFD
	DONT byte = 0xFE
	SB   byte = 0xFA
	SE   byte = 0xF0

	OptEcho            byte = 0x01
	OptSuppressGoAhead byte = 0x03
	OptTerminalType    byte = 0x18
	OptWindowSize      byte = 0x1F
)

// stripIAC removes all IAC sequences from the input data
func stripIAC(data []byte) []byte {
	result := make([]byte, 0, len(data))
	i := 0
	for i < len(data) {
		if data[i] == IAC && i+1 < len(data) {
			cmd := data[i+1]
			switch cmd {
			case WILL, WONT, DO, DONT:
				i += 3 // IAC + cmd + option
			case SB:
				// Skip to SE
				i += 2
				for i < len(data) {
					if data[i] == IAC && i+1 < len(data) && data[i+1] == SE {
						i += 2
						break
					}
					i++
				}
			case IAC:
				result = append(result, IAC) // escaped IAC
				i += 2
			default:
				i += 2
			}
		} else {
			result = append(result, data[i])
			i++
		}
	}
	return result
}

// negotiateOptions sends initial IAC negotiations to the client
func negotiateOptions(w io.Writer) error {
	// WILL ECHO (server will echo characters)
	// WILL SUPPRESS-GO-AHEAD
	// DO TERMINAL-TYPE
	opts := []byte{
		IAC, WILL, OptEcho,
		IAC, WILL, OptSuppressGoAhead,
		IAC, DO, OptTerminalType,
	}
	_, err := w.Write(opts)
	return err
}

// disableEcho sends IAC WILL ECHO (server echoes, client should not)
func disableEcho(w io.Writer) error {
	_, err := w.Write([]byte{IAC, WILL, OptEcho})
	return err
}

// enableEcho sends IAC WONT ECHO (server stops echoing, client should echo locally)
func enableEcho(w io.Writer) error {
	_, err := w.Write([]byte{IAC, WONT, OptEcho})
	return err
}
