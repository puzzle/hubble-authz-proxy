// Package proxy sits between the Hubble UI frontend and its unmodified backend,
// relaying requests untouched and filtering namespace-scoped data out of the
// responses before they reach the browser.
package proxy

import (
	"encoding/json"

	cppb "github.com/cilium/hubble-ui/backend/proto/customprotocol"
	"google.golang.org/protobuf/proto"
)

// The hubble-ui backend wraps every response in a customprotocol.Message. The
// envelope is encoded either as binary protobuf (content-type
// application/octet-stream) or as JSON (application/json).
//
// The JSON form is produced by the backend with plain encoding/json over the
// generated struct — NOT protojson — so we must mirror that exactly or field
// names and the base64 body would not round-trip. See the backend's
// message.Serialize.
//
// Body.Content is always binary protobuf regardless of the envelope encoding:
// the backend marshals the ui.* payload with proto.Marshal before wrapping.

func decodeEnvelope(b []byte, isJSON bool) (*cppb.Message, error) {
	msg := &cppb.Message{}
	if isJSON {
		return msg, json.Unmarshal(b, msg)
	}
	return msg, proto.Unmarshal(b, msg)
}

func encodeEnvelope(msg *cppb.Message, isJSON bool) ([]byte, error) {
	if isJSON {
		return json.Marshal(msg)
	}
	return proto.Marshal(msg)
}
