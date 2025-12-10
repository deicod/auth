package repos

import (
	"context"
	"errors"
	"time"

	"github.com/deicod/auth/internal/ctxutil"
	"github.com/deicod/auth/mgo/models"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type PasswordResetRepository struct {
	coll    *mongo.Collection
	timeout time.Duration
}

func NewPasswordResetRepository(coll *mongo.Collection, timeout time.Duration) *PasswordResetRepository {
	return &PasswordResetRepository{coll: coll, timeout: timeout}
}

func (r *PasswordResetRepository) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

func (r *PasswordResetRepository) Create(ctx context.Context, token models.PasswordReset) (models.PasswordReset, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.coll.InsertOne(ctx, token)
	return token, ctxutil.NormalizeError(err, "mgo.password_reset.insert")
}

func (r *PasswordResetRepository) FindByHash(ctx context.Context, hash string) (models.PasswordReset, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	var token models.PasswordReset
	err := r.coll.FindOne(ctx, bson.M{"token_hash": hash}).Decode(&token)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return token, err
		}
		return token, ctxutil.NormalizeError(err, "mgo.password_reset.find_by_hash")
	}
	return token, nil
}

func (r *PasswordResetRepository) Consume(ctx context.Context, id bson.ObjectID, consumedAt time.Time) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.coll.UpdateByID(ctx, id, bson.M{"$set": bson.M{"consumed_at": consumedAt}})
	return ctxutil.NormalizeError(err, "mgo.password_reset.consume")
}
