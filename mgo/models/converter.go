package models

import (
	"fmt"

	"github.com/deicod/auth/core"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func ObjectIDFromCore(id core.ID) (primitive.ObjectID, error) {
	if id == "" {
		return primitive.NilObjectID, nil
	}
	oid, err := primitive.ObjectIDFromHex(string(id))
	if err != nil {
		return primitive.NilObjectID, fmt.Errorf("invalid id: %w", err)
	}
	return oid, nil
}

func CoreIDFromObjectID(oid primitive.ObjectID) core.ID {
	if oid == primitive.NilObjectID {
		return ""
	}
	return core.ID(oid.Hex())
}
