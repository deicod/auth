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

type VerificationRepository struct {
	coll    *mongo.Collection
	timeout time.Duration
}

func NewVerificationRepository(coll *mongo.Collection, timeout time.Duration) *VerificationRepository {
	return &VerificationRepository{coll: coll, timeout: timeout}
}

func (r *VerificationRepository) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

func (r *VerificationRepository) Create(ctx context.Context, token models.VerificationToken) (models.VerificationToken, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.coll.InsertOne(ctx, token)
	return token, ctxutil.NormalizeError(err, "mgo.verification.insert")
}

func (r *VerificationRepository) FindByHash(ctx context.Context, hash string) (models.VerificationToken, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	var token models.VerificationToken
	err := r.coll.FindOne(ctx, bson.M{"token_hash": hash}).Decode(&token)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return token, err
		}
		return token, ctxutil.NormalizeError(err, "mgo.verification.find_by_hash")
	}
	return token, nil
}

func (r *VerificationRepository) Consume(ctx context.Context, id bson.ObjectID, consumedAt time.Time) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	update := bson.M{"$set": bson.M{"consumed_at": consumedAt}}
	_, err := r.coll.UpdateByID(ctx, id, update)
	return ctxutil.NormalizeError(err, "mgo.verification.consume")
}

func (r *VerificationRepository) DeleteByID(ctx context.Context, id bson.ObjectID) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.coll.DeleteOne(ctx, bson.M{"_id": id})
	return ctxutil.NormalizeError(err, "mgo.verification.delete")
}
