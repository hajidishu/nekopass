package control

import (
	"net/http"
	"strconv"
)

// Only POST collection endpoints may omit an ID and create a resource.
func resourceID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := r.PathValue("id")
	if raw == "" && r.Method == http.MethodPost {
		return 0, true
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		fail(w, 400, "资源 ID 无效")
		return 0, false
	}
	return id, true
}
