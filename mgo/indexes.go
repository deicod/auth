package mgo

import (
	"context"
	"fmt"
	"time"

	"github.com/deicod/auth/core"
	"github.com/deicod/auth/mgo/repos"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func ensureIndexes(ctx context.Context, db *mongo.Database, cfg Config) error {
	timeout := cfg.OperationTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Add the race guard without rewriting accounts or dropping the legacy
	// unique index. A failed build leaves legacy data and indexes intact.
	_, err := db.Collection(cfg.UsersCollection).Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetName("users_username_nocase_unique").SetUnique(true).SetCollation(repos.UsernameCollation()),
	})
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("%w: resolve existing case-insensitive username collisions before restarting auth", core.ErrUsernameExists)
		}
		return err
	}

	ttlIndex := func(name string) *options.IndexOptionsBuilder {
		return options.Index().SetExpireAfterSeconds(0).SetName(name)
	}

	uniqIndex := func(name string) *options.IndexOptionsBuilder {
		return options.Index().SetUnique(true).SetName(name)
	}

	collections := []struct {
		coll   *mongo.Collection
		models []mongo.IndexModel
	}{
		{
			coll: db.Collection(cfg.UsersCollection),
			models: []mongo.IndexModel{
				{Keys: bson.D{{Key: "email", Value: 1}}, Options: uniqIndex("users_email_unique")},
				{Keys: bson.D{{Key: "username", Value: 1}}, Options: uniqIndex("users_username_unique")},
			},
		},
		{
			coll: db.Collection(cfg.SessionsCollection),
			models: []mongo.IndexModel{
				{Keys: bson.D{{Key: "token_hash", Value: 1}}, Options: uniqIndex("sessions_token_hash_unique")},
				{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: ttlIndex("sessions_expires_ttl")},
			},
		},
		{
			coll: db.Collection(cfg.VerificationCollection),
			models: []mongo.IndexModel{
				{Keys: bson.D{{Key: "token_hash", Value: 1}}, Options: uniqIndex("verifications_token_hash_unique")},
				{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: ttlIndex("verifications_expires_ttl")},
			},
		},
		{
			coll: db.Collection(cfg.PasswordResetCollection),
			models: []mongo.IndexModel{
				{Keys: bson.D{{Key: "token_hash", Value: 1}}, Options: uniqIndex("password_resets_token_hash_unique")},
				{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: ttlIndex("password_resets_expires_ttl")},
			},
		},
		{
			coll: db.Collection(cfg.EmailChangeCollection),
			models: []mongo.IndexModel{
				{Keys: bson.D{{Key: "token_hash", Value: 1}}, Options: uniqIndex("email_changes_token_hash_unique")},
				{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: ttlIndex("email_changes_expires_ttl")},
			},
		},
	}

	for _, group := range collections {
		if len(group.models) == 0 {
			continue
		}
		if _, err := group.coll.Indexes().CreateMany(ctx, group.models); err != nil {
			return err
		}
	}
	return nil
}
