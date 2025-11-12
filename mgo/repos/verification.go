package repos

import (
	"context"
	"time"

	"github.com/deicod/auth/mgo/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
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
	return token, err
}

func (r *VerificationRepository) FindByHash(ctx context.Context, hash string) (models.VerificationToken, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	var token models.VerificationToken
	err := r.coll.FindOne(ctx, bson.M{"token_hash": hash}).Decode(&token)
	return token, err
}

func (r *VerificationRepository) Consume(ctx context.Context, id primitive.ObjectID, consumedAt time.Time) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	update := bson.M{"$set": bson.M{"consumed_at": consumedAt}}
	_, err := r.coll.UpdateByID(ctx, id, update)
	return err
}

func (r *VerificationRepository) DeleteByID(ctx context.Context, id primitive.ObjectID) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.coll.DeleteOne(ctx, bson.M{"_id": id})
	return err
}
