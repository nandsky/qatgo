package server

import "testing"

func TestStartCyService(t *testing.T) {
	err := StartCyService()
	if err != nil {
		t.Log(err)
		return
	}

}
