package utils

import (
	"encoding/json"
	"net/http"
)

func ReadJSON(w http.ResponseWriter, r *http.Request, value any) error {
	maxBytes := int64(1_048_576) // 1 MB
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	return decoder.Decode(value)
}

func WriteJSON(w http.ResponseWriter, status int, value any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	return json.NewEncoder(w).Encode(value)
}
