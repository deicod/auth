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

type EmailChangeRepository struct {
	coll    *mongo.Collection
	timeout time.Duration
}

func NewEmailChangeRepository(coll *mongo.Collection, timeout time.Duration) *EmailChangeRepository {
	return &EmailChangeRepository{coll: coll, timeout: timeout}
}

func (r *EmailChangeRepository) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

func (r *EmailChangeRepository) Create(ctx context.Context, req models.EmailChange) (models.EmailChange, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.coll.InsertOne(ctx, req)
	return req, ctxutil.NormalizeError(err, "mgo.email_change.insert")
}

func (r *EmailChangeRepository) FindByHash(ctx context.Context, hash string) (models.EmailChange, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	var req models.EmailChange
	err := r.coll.FindOne(ctx, bson.M{"token_hash": hash}).Decode(&req)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return req, err
		}
		return req, ctxutil.NormalizeError(err, "mgo.email_change.find_by_hash")
	}
	return req, nil
}

func (r *EmailChangeRepository) Consume(ctx context.Context, id bson.ObjectID, consumedAt time.Time) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.coll.UpdateByID(ctx, id, bson.M{"$set": bson.M{"consumed_at": consumedAt}})
	return ctxutil.NormalizeError(err, "mgo.email_change.consume")
}
