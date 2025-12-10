package models

import (
	"fmt"

	"github.com/deicod/auth/core"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func ObjectIDFromCore(id core.ID) (bson.ObjectID, error) {
	if id == "" {
		return bson.NilObjectID, nil
	}
	oid, err := bson.ObjectIDFromHex(string(id))
	if err != nil {
		return bson.NilObjectID, fmt.Errorf("invalid id: %w", err)
	}
	return oid, nil
}

func CoreIDFromObjectID(oid bson.ObjectID) core.ID {
	if oid == bson.NilObjectID {
		return ""
	}
	return core.ID(oid.Hex())
}
